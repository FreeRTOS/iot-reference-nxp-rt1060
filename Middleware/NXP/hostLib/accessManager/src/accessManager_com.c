/**
* @file accessManager_com.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2016,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* This file implements basic communication functionality between Host and
* Secure element.
* @par History
*
*****************************************************************************/
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "nxLog_App.h"

#include "accessManager_com.h"

#if defined(SCI2C)
#include "smComSCI2C.h"
#endif
#if defined(SPI)
#include "smComSCSPI.h"
#endif
#if defined(PCSC)
#include "smComPCSC.h"
#endif
#if defined(SMCOM_JRCP_V2)
#include "smComJRCP.h"
#endif
#if defined(RJCT_VCOM)
#include "smComSerial.h"
#endif
#if defined(T1oI2C)
#include "smComT1oI2C.h"
#endif
#if defined(SMCOM_PN7150)
#include "smComPN7150.h"
#endif
#if defined(SMCOM_THREAD)
#include "smComThread.h"
#endif

#include "global_platf.h"

#if SSS_HAVE_SCP_SCP03_SSS
#include "ex_sss_boot.h"
#include "ex_sss_auth.h"
#include "fsl_sss_api.h"
#include "ex_sss_scp03_keys.h"
#include "nxEnsure.h"
#include "fsl_sss_se05x_scp03.h"
#endif // SSS_HAVE_SCP_SCP03_SSS

#if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)
#include "ex_sss_boot.h"
#include "ex_sss_auth.h"
#include "fsl_sss_api.h"
#include "ex_sss_scp03_keys.h"
#include "nxEnsure.h"
#include "ex_a71ch_scp03.h"
#include "sm_apdu.h"
#endif // #if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)

#ifndef FLOW_VERBOSE
#define FLOW_VERBOSE
#endif

#ifdef FLOW_VERBOSE
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

#if (SSS_HAVE_SCP_SCP03_SSS || SSS_HAVE_SCP_SCP03_HOSTCRYPTO)
static sss_key_store_t gHostKs;
static sss_session_t gHostSession;
#endif

#if SSS_HAVE_SCP_SCP03_SSS
#define SCP03_MAX_AUTH_KEY_SIZE 52
#define AUTH_KEY_SIZE 16

static NXSCP03_AuthCtx_t gAuthCtx;
static ex_SE05x_authCtx_t gEx_auth;
static Se05xSession_t gSe05xSession;

static sss_status_t Alloc_Scp03key_toSE05xAuthctx(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId)
{
    sss_status_t status = kStatus_SSS_Fail;
    status              = sss_host_key_object_init(keyObject, pKs);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = sss_host_key_object_allocate_handle(keyObject,
        keyId,
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        SCP03_MAX_AUTH_KEY_SIZE,
        kKeyObject_Mode_Transient);
    return status;
}

/* Function to Set Init and Allocate static Scp03Keys and Init Allocate dynamic keys */
static sss_status_t ex_sss_se05x_prepare_host_platformscp(
    NXSCP03_AuthCtx_t *pAuthCtx, ex_SE05x_authCtx_t *pEx_auth, sss_key_store_t *pKs)
{
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t KEY_ENC[]   = EX_SSS_AUTH_SE05X_KEY_ENC;
    uint8_t KEY_MAC[]   = EX_SSS_AUTH_SE05X_KEY_MAC;
    uint8_t KEY_DEK[]   = EX_SSS_AUTH_SE05X_KEY_DEK;

#ifdef EX_SSS_SCP03_FILE_PATH

    uint8_t enc[AUTH_KEY_SIZE] = {0};
    uint8_t mac[AUTH_KEY_SIZE] = {0};
    uint8_t dek[AUTH_KEY_SIZE] = {0};

    status = scp03_keys_from_path(&enc[0], sizeof(enc), &mac[0], sizeof(mac), &dek[0], sizeof(dek));

    if (status == kStatus_SSS_Success) {
        memcpy(KEY_ENC, enc, sizeof(KEY_ENC));
        memcpy(KEY_MAC, mac, sizeof(KEY_MAC));
        memcpy(KEY_DEK, dek, sizeof(KEY_DEK));
    }

#endif // EX_SSS_SCP03_FILE_PATH

    pAuthCtx->pStatic_ctx            = &pEx_auth->scp03.ex_static;
    pAuthCtx->pDyn_ctx               = &pEx_auth->scp03.ex_dyn;
    NXSCP03_StaticCtx_t *pStatic_ctx = pAuthCtx->pStatic_ctx;
    NXSCP03_DynCtx_t *pDyn_ctx       = pAuthCtx->pDyn_ctx;

    pStatic_ctx->keyVerNo = EX_SSS_AUTH_SE05X_KEY_VERSION_NO;

    /* Init Allocate ENC Static Key */
    status = Alloc_Scp03key_toSE05xAuthctx(&pStatic_ctx->Enc, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set ENC Static Key */
    status = sss_host_key_store_set_key(pKs, &pStatic_ctx->Enc, KEY_ENC, sizeof(KEY_ENC), sizeof(KEY_ENC) * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate MAC Static Key */
    status = Alloc_Scp03key_toSE05xAuthctx(&pStatic_ctx->Mac, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set MAC Static Key */
    status = sss_host_key_store_set_key(pKs, &pStatic_ctx->Mac, KEY_MAC, sizeof(KEY_MAC), sizeof(KEY_MAC) * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate DEK Static Key */
    status = Alloc_Scp03key_toSE05xAuthctx(&pStatic_ctx->Dek, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Set DEK Static Key */
    status = sss_host_key_store_set_key(pKs, &pStatic_ctx->Dek, KEY_DEK, sizeof(KEY_DEK), sizeof(KEY_DEK) * 8, NULL, 0);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init Allocate ENC Session Key */
    status = Alloc_Scp03key_toSE05xAuthctx(&pDyn_ctx->Enc, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Init Allocate MAC Session Key */
    status = Alloc_Scp03key_toSE05xAuthctx(&pDyn_ctx->Mac, pKs, MAKE_TEST_ID(__LINE__));
    if (status != kStatus_SSS_Success) {
        return status;
    }
    /* Init Allocate DEK Session Key */
    status = Alloc_Scp03key_toSE05xAuthctx(&pDyn_ctx->Rmac, pKs, MAKE_TEST_ID(__LINE__));
    return status;
}

static smStatus_t sss_gen_TXn(struct Se05xSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle);

static smStatus_t sss_gen_transmit(
    SE_AuthType_t currAuth,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle);

static smStatus_t sss_gen_channel_txnRaw(const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle);

#endif // SSS_HAVE_SCP_SCP03_SSS


/**
 * SM_ConnectAm
 * @param[in] commState
 * @param[out] atr
 * @param[in,out] atrLen
 * @return ::ERR_CONNECT_LINK_FAILED    No communication with TDA chip (and/or) Secure Module
 * @return ::SMCOM_COM_FAILED           Cannot open communication channel on the Host
 * @return ::SMCOM_PROTOCOL_FAILED      No communication with Secure Module
 * @return 0x9000                       OK
 */
U16 SM_ConnectAm(SmCommStateAm_t *commState, U8 *atr, U16 *atrLen)
{
    U16 sw = SW_OK;
    U16 uartBR = 0;
    U16 t1BR = 0;
#if defined(SCI2C) || defined(T1oI2C) || defined(SMCOM_JRCP_V2)
    U8 dummyAtr[64];
    U16 dummyAtrLen = sizeof(dummyAtr);
    U8 precookedI2cATR[] = {
        0x3B, 0xFB, 0x18, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x45, 0x50, 0x4C, 0x41, 0x43, 0x45, 0x48, 0x4F, 0x4C,
        0x44, 0x45, 0x52, 0xAB};
#endif

#ifndef A71_IGNORE_PARAM_CHECK
    if ((commState == NULL) || (atr == NULL) || (atrLen == 0)) {
        return ERR_API_ERROR;
    }
#endif

#ifdef SMCOM_PN7150
    sw = smComPN7150_Open(0, 0x00, atr, atrLen);
#elif defined(SCI2C)
    // The smComSCI2C_Open function returns an SCI2C compliant ATR value.
    // This value can not be used as is as ATR parameter to the SM_Connect function because it is
    // not ISO7816-3 compliant. Instead a pre-cooked value is used.
    // In case no SCI2C ATR can be retrieved by smComSCI2C_Open, no Secure Element is attached.
    sw = smComSCI2C_Open(NULL, ESTABLISH_SCI2C, 0x00, dummyAtr, &dummyAtrLen);
#elif defined(PCSC)
    sw = smComPCSC_Open(0, atr, atrLen);
#elif defined(T1oI2C)
    sw = smComT1oI2C_Open(NULL, ESE_MODE_NORMAL, 0x00, dummyAtr, &dummyAtrLen);
#elif defined(SMCOM_JRCP_V2)
    // Rely on default settings / env variable to select correct IP:PORT
    sw = smComJRCP_Open(NULL, NULL, 0);
#endif
    commState->param1 = t1BR;
    commState->param2 = uartBR;

#if defined(T1oI2C) || defined(SCI2C) || defined(SMCOM_JRCP_V2)
    if (sw == SW_OK)
    {
        if (dummyAtrLen == 0)
        {
#ifdef T1oI2C
            FPRINTF("smComT1oI2C_Open failed. No secure module attached");
#elif defined(SCI2C)
            FPRINTF("smComSCI2C_Open failed. No secure module attached");
#elif defined (SMCOM_JRCP_V2)
            FPRINTF("smComJRCP_Open failed. No secure module attached");
#endif
            *atrLen = 0;
            return ERR_CONNECT_LINK_FAILED;
        }
        else
        {
#if defined(T1oI2C) || defined(SCI2C)
            int i = 0;
            FPRINTF("DUMMY_ATR=0x");
            for (i=0; i<dummyAtrLen; i++) FPRINTF("%02X.", dummyAtr[i]);
            FPRINTF("\n");
#endif
        }
        FPRINTF("Replacing *_ATR by default (pre-cooked) ATR.\n");
        memcpy(atr, precookedI2cATR, sizeof(precookedI2cATR));
        *atrLen = sizeof(precookedI2cATR);
    }
#endif // defined(T1oI2C) || defined(SCI2C) || defined(SMCOM_JRCP_V2)
    return sw;
}



#if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)
U16 SM_SendAPDUAm(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen, U8 platformSCP03_On)
{
    U32 status = 0;
    U32 respLenLocal = 0;
    U8 sharedApduBuffer[MAX_APDU_BUF_LENGTH] = {0,};
    apdu_t sharedApdu = {0,};
    scp_CommandType_t channelType = 0;

    apdu_t* pApdu = &sharedApdu;
    pApdu->pBuf = sharedApduBuffer;

    ENSURE_OR_GO_EXIT(cmd != NULL);
    ENSURE_OR_GO_EXIT(cmdLen > 0);
    ENSURE_OR_GO_EXIT(resp != NULL);
    ENSURE_OR_GO_EXIT(respLen != NULL);

    respLenLocal = *respLen;

    if (cmd[0] != AX_CLA) {
        status = smCom_TransceiveRaw(NULL, cmd, cmdLen, resp, &respLenLocal);
        *respLen = (U16)respLenLocal;
        goto exit;
    }

    ENSURE_OR_GO_EXIT(cmdLen >= 12);

    if ( (cmd[0] == AX_CLA) && (cmd[1] == A71CH_INS_ERASE_MODULE) && (cmd[2] == P1_RESET) && (cmd[3] == P2_RESET) ) {
        /* Ignore debug reset command issued. */
        LOG_W("Debug reset command is ignored.\n");
        ENSURE_OR_GO_EXIT(*respLen >= 2);
        resp[0] = 0x90;
        resp[1] = 0x00;
        *respLen = 2;
        status = SMCOM_OK;
        goto exit;
    }

    pApdu->cla = cmd[0];
    pApdu->ins = cmd[1];
    pApdu->p1 = cmd[2];
    pApdu->p2 = cmd[3];

    pApdu->extendedLength = cmd[cmdLen-12];
    pApdu->hasData = cmd[cmdLen-11];
    pApdu->lc = cmd[cmdLen-10] | cmd[cmdLen-9] << 8;
    pApdu->lcLength = cmd[cmdLen-8];
    pApdu->hasLe = cmd[cmdLen-7];
    pApdu->le = cmd[cmdLen-6] | cmd[cmdLen-5] << 8;
    pApdu->leLength = cmd[cmdLen-4];
    pApdu->offset = cmd[cmdLen-3] | cmd[cmdLen-2] << 8;

    channelType = cmd[cmdLen-1];

    /* 12 bytes additional data copied to buffer for PlatformSCP03 case */
    ENSURE_OR_GO_EXIT(cmdLen - 12 < MAX_APDU_BUF_LENGTH);
    pApdu->buflen = cmdLen - 12;
    memcpy(pApdu->pBuf, cmd, cmdLen - 12);

    if (platformSCP03_On != 0) {
#if SSS_HAVE_SCP_SCP03_HOSTCRYPTO
#else
        LOG_E("To enable PlatformSCP03 support include support in cmake build.\n");
        LOG_E(" cmake -DSCP:STRING=SCP03_HOSTCRYPTO -DA71CH_AUTH=SCP03 .");
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
#endif
    }

    status = scp_Transceive(NULL, pApdu, SCP_MODE);
    if (status != SMCOM_OK) {
        goto exit;
    }

    if (pApdu->rxlen > (*respLen)) {
        status = 0;
        goto exit;
    }

    memcpy(resp, pApdu->pBuf, pApdu->rxlen);
    *respLen = (U16)pApdu->rxlen;

exit:
    return (U16) status;
}

#else
U16 SM_SendAPDUAm(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen, U8 platformSCP03_On)
{
    U32 status = 0;

    if (platformSCP03_On != 0) {
#if SSS_HAVE_SCP_SCP03_SSS
        smStatus_t smStatus;
        Se05xSession_t *se05xSession = &gSe05xSession;
        size_t pRspBufLen = (size_t)(*respLen);

        smStatus = DoAPDUTxRx(se05xSession, cmd, (size_t) cmdLen, resp, &pRspBufLen);
        *respLen = (U16)pRspBufLen;
        FPRINTF("SM_SendAPDUAm: smStatus = 0x%04X\n", smStatus);
        status = smStatus;
#else
        LOG_E("To enable PlatformSCP03 support include support in cmake build.\n");
        LOG_E(" cmake -DSCP:STRING=SCP03_SSS -DSE05X_Auth:STRING=PlatfSCP03 .");
        status = ERR_NOT_IMPLEMENTED;
#endif
    }
    else {
        U32 respLenLocal = *respLen;
        status = smCom_TransceiveRaw(NULL, cmd, cmdLen, resp, &respLenLocal);
        *respLen = (U16)respLenLocal;
    }

    return (U16) status;
}
#endif

U16 SM_CloseAm(U8 mode)
{
    U16 sw = SW_OK;

#if defined(SCI2C)
    sw = smComSCI2C_Close(mode);
#endif
#if defined(PCSC)
    sw = smComPCSC_Close(mode);
#endif
#if defined(T1oI2C)
    sw = smComT1oI2C_Close(NULL, mode);
#endif
#if defined(SMCOM_JRCP_V1)
    AX_UNUSED_ARG(mode);
    sw = smComSocket_Close();
#endif
#if defined(SMCOM_JRCP_V2)
    AX_UNUSED_ARG(mode);
    sw = smComJRCP_Close(NULL, mode);
#endif
#if defined(RJCT_VCOM)
    AX_UNUSED_ARG(mode);
    sw = smComVCom_Close(NULL);
#endif
#if defined(SMCOM_THREAD)
    AX_UNUSED_ARG(mode);
    sw = smComThread_Close();
#endif
    smCom_DeInit();

    return sw;
}

U16 SM_EstablishPlatformSCP03Am(SmCommStateAm_t *commState)
{
#if SSS_HAVE_SCP_SCP03_SSS
    U16 sw = SW_OK;

    sss_status_t status = kStatus_SSS_Fail;
    sss_type_t hostsubsystem = kType_SSS_SubSystem_NONE;
    Se05xSession_t *se05xSession = &gSe05xSession;

    printf("SM_EstablishPlatformSCP03Am (Entry)\n");

#if SSS_HAVE_MBEDTLS
        hostsubsystem = kType_SSS_mbedTLS;
#elif SSS_HAVE_OPENSSL
        hostsubsystem = kType_SSS_OpenSSL;
#elif SSS_HAVE_HOSTCRYPTO_USER
        hostsubsystem = kType_SSS_Software;
#endif

    status = sss_host_session_open(&gHostSession, hostsubsystem, 0, kSSS_ConnectionType_Plain, NULL);
    if (kStatus_SSS_Success != status) {
        LOG_E("Failed to open Host Session");
        sw = ERR_GENERAL_ERROR;
        goto cleanup;
    }

    status = sss_host_key_store_context_init(&gHostKs, &gHostSession);
    if (kStatus_SSS_Success != status) {
        LOG_E("Host: sss_key_store_context_init failed");
        sw = ERR_GENERAL_ERROR;
        goto cleanup;
    }

    status = sss_host_key_store_allocate(&gHostKs, __LINE__);
    if (kStatus_SSS_Success != status) {
        LOG_E("Host: sss_key_store_allocate failed");
        sw = ERR_GENERAL_ERROR;
        goto cleanup;
    }

    ex_sss_se05x_prepare_host_platformscp(&gAuthCtx, &gEx_auth, &gHostKs);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_se05x_prepare_host_platformscp failed");
        sw = ERR_GENERAL_ERROR;
        goto cleanup;
    }

    se05xSession->fp_TXn      = &sss_gen_TXn;
    se05xSession->fp_Transmit = &sss_gen_transmit;

    se05xSession->fp_Transform = &se05x_Transform;
    se05xSession->fp_DeCrypt   = &se05x_DeCrypt;
    se05xSession->authType     = kSSS_AuthType_SCP03;
    status                     = nxScp03_AuthenticateChannel(se05xSession, &gAuthCtx);
    if (status == kStatus_SSS_Success) {
        /* Platform SCP03 differs between SE050 and SE051. */
        if (commState->appletVersion >= 0x04030000) {
            FPRINTF("SE051 connected.\n");
            gAuthCtx.pDyn_ctx->authType = (uint8_t)kSSS_AuthType_AESKey;
        }
        else {
            FPRINTF("SE050 connected.\n");
            gAuthCtx.pDyn_ctx->authType = (uint8_t)kSSS_AuthType_SCP03;
        }
        /*Auth type to Platform SCP03 again as channel authentication will modify it
        to auth type None*/
        se05xSession->authType     = kSSS_AuthType_SCP03;
        se05xSession->pdynScp03Ctx = gAuthCtx.pDyn_ctx;
        sw                         = SM_OK;
        se05xSession->fp_Transform = &se05x_Transform_scp;
    }
    else {
        LOG_E("Could not set SCP03 Secure Channel");
        sw = SCP_FAIL;
    }

    printf("SM_EstablishPlatformSCP03Am (Exit); Status = 0x%04X\n", sw);

cleanup:
    return sw;
#else
    return ERR_NOT_IMPLEMENTED;
#endif // SSS_HAVE_SCP_SCP03_SSS
}

#if SSS_HAVE_SCP_SCP03_SSS

static smStatus_t sss_gen_TXn(struct Se05xSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle)
{
    smStatus_t ret = SM_NOT_OK;
    tlvHeader_t outHdr = {
        0,
    };
    uint8_t txBuf[1024] = {
        0,
    };
    size_t txBufLen = sizeof(txBuf);

    ret = pSession->fp_Transform(
        pSession, hdr, cmdBuf, cmdBufLen, &outHdr, txBuf, &txBufLen, hasle);
    ENSURE_OR_GO_EXIT(ret == SM_OK);

    ret = pSession->fp_Transmit(
        pSession->authType,
        &outHdr,
        txBuf,
        txBufLen,
        rsp,
        rspLen,
        hasle);

    if (pSession->authType == kSSS_AuthType_SCP03)
    {
        ret = pSession->fp_DeCrypt(pSession, cmdBufLen, rsp, rspLen, hasle);
    }

    ENSURE_OR_GO_EXIT(ret == SM_OK);
exit:
    return ret;
}


static smStatus_t sss_gen_transmit(
    SE_AuthType_t currAuth,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle)
{
    smStatus_t retStatus = SM_NOT_OK;

    if (currAuth == kSSS_AuthType_SCP03) {
        uint32_t u32rspLen = (uint32_t)*rspLen;
        retStatus = (smStatus_t)smCom_TransceiveRaw(
            NULL, cmdBuf, (uint16_t)cmdBufLen, rsp, &u32rspLen);
        ENSURE_OR_GO_EXIT(retStatus == SM_OK);
        *rspLen = u32rspLen;
    }
    else {
        retStatus = sss_gen_channel_txnRaw(
            hdr, cmdBuf, cmdBufLen, rsp, rspLen, hasle);
        ENSURE_OR_GO_EXIT(retStatus == SM_OK);
    }

exit:
    return retStatus;
}


static smStatus_t sss_gen_channel_txnRaw(const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle)
{
    uint8_t txBuf[1024] = { 0 };
    int i = 0;
    memcpy(&txBuf[i], hdr, sizeof(*hdr));
    smStatus_t ret = SM_NOT_OK;
    i += sizeof(*hdr);
    if (cmdBufLen > 0) {
        // The Lc field must be extended in case the length does not fit
        // into a single byte (Note, while the standard would allow to
        // encode 0x100 as 0x00 in the Lc field, nobody who is sane in his mind
        // would actually do that).
        if ((cmdBufLen < 0xFF) && !hasle) {
            txBuf[i++] = (uint8_t)cmdBufLen;
        }
        else {
            txBuf[i++] = 0x00;
            txBuf[i++] = 0xFFu & (cmdBufLen >> 8);
            txBuf[i++] = 0xFFu & (cmdBufLen);
        }
        memcpy(&txBuf[i], cmdBuf, cmdBufLen);
        i += cmdBufLen;
    }
    if (hasle) {
        txBuf[i++] = 0x00;
        txBuf[i++] = 0x00;
    }
    uint32_t U32rspLen = (uint32_t)*rspLen;
    ret = smCom_TransceiveRaw(NULL, txBuf, i, rsp, &U32rspLen);
    *rspLen = U32rspLen;
    return ret;
}

#endif // SSS_HAVE_SCP_SCP03_SSS


#if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)

U16 a71chGetScpKeysFromKeyfile(U8 *enc, U8 *mac, U8 *dek, char *szKeyFile);

U16 SM_EstablishA71CHPlatformSCP03Am()
{
#if SSS_HAVE_SCP_SCP03_HOSTCRYPTO
    U16 sw = SW_OK;

    sss_status_t status = kStatus_SSS_Fail;
    sss_type_t hostsubsystem = kType_SSS_SubSystem_NONE;
    uint8_t KEY_ENC[]   = SCP03_A71CH_KEY_ENC;
    uint8_t KEY_MAC[]   = SCP03_A71CH_KEY_MAC;
    uint8_t KEY_DEK[]   = SCP03_A71CH_KEY_DEK;

    printf("SM_EstablishA71CHPlatformSCP03Am (Entry)\n");

#if SSS_HAVE_MBEDTLS
        hostsubsystem = kType_SSS_mbedTLS;
#elif SSS_HAVE_OPENSSL
        hostsubsystem = kType_SSS_OpenSSL;
#elif SSS_HAVE_HOSTCRYPTO_USER
        hostsubsystem = kType_SSS_Software;
#endif

    status = sss_host_session_open(&gHostSession, hostsubsystem, 0, kSSS_ConnectionType_Plain, NULL);
    if (kStatus_SSS_Success != status) {
        LOG_E("Failed to open Host Session");
        sw = ERR_GENERAL_ERROR;
        goto cleanup;
    }

    status = sss_host_key_store_context_init(&gHostKs, &gHostSession);
    if (kStatus_SSS_Success != status) {
        LOG_E("Host: sss_key_store_context_init failed");
        sw = ERR_GENERAL_ERROR;
        goto cleanup;
    }

    status = sss_host_key_store_allocate(&gHostKs, __LINE__);
    if (kStatus_SSS_Success != status) {
        LOG_E("Host: sss_key_store_allocate failed");
        sw = ERR_GENERAL_ERROR;
        goto cleanup;
    }

    LOG_I("A71CH SCP03 add-on");
    {
        // Variables used by calls to legacy API
        U8 sCounter[3];
        U16 sCounterLen = sizeof(sCounter);
        U16 sw          = 0;
        U8 scpKeyEncBase[SCP_KEY_SIZE] = {0,};
        U8 scpKeyMacBase[SCP_KEY_SIZE] = {0,};
        U8 scpKeyDekBase[SCP_KEY_SIZE] = {0,};
        char *scp03_path_env = getenv(A71CH_SCP03_PATH_ENV);

        if (scp03_path_env != NULL) {
            LOG_W("Using SCP03 keys from:'%s' (ENV=%s)", scp03_path_env, A71CH_SCP03_PATH_ENV);
            sw = a71chGetScpKeysFromKeyfile(scpKeyEncBase, scpKeyMacBase, scpKeyDekBase, scp03_path_env);
            status = (sw == SW_OK) ? kStatus_SSS_Success : kStatus_SSS_Fail;
            if (kStatus_SSS_Success != status) {
                LOG_E("a71chGetScpKeysFromKeyfile failed");
                sw = ERR_GENERAL_ERROR;
                goto cleanup;
            }
        }
        else {
            memcpy(scpKeyEncBase, KEY_ENC, sizeof(KEY_ENC));
            memcpy(scpKeyMacBase, KEY_MAC, sizeof(KEY_MAC));
            memcpy(scpKeyDekBase, KEY_DEK, sizeof(KEY_DEK));
            LOG_I(
                "Using default PlatfSCP03 keys. "
                "You can use keys from file using ENV=%s",
                A71CH_SCP03_PATH_ENV);
        }

        LOG_I("Clear host-side SCP03 channel state");
        DEV_ClearChannelState();

        LOG_I("SCP_Authenticate()");
        sw     = SCP_Authenticate(scpKeyEncBase, scpKeyMacBase, scpKeyDekBase, SCP_KEY_SIZE, sCounter, &sCounterLen);
        status = (sw == SW_OK) ? kStatus_SSS_Success : kStatus_SSS_Fail;
        if (kStatus_SSS_Success != status) {
            LOG_E("SCP_Authenticate failed");
            sw = ERR_GENERAL_ERROR;
            goto cleanup;
        }

        LOG_I("** Establish SCP03 session: End **");
    }

cleanup:
    return sw;
#else
    return ERR_NOT_IMPLEMENTED;
#endif // SSS_HAVE_SCP_SCP03_HostCrypto
}

#endif //#if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)
