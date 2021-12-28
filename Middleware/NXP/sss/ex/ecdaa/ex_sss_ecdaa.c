/*
 *
 * Copyright 2018,2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <nxEnsure.h>
#include <nxLog_App.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define KEY_BIT_LENGTH 256
/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_ecdaa_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_ecdaa_boot_ctx)
#define EX_SSS_BOOT_DO_ERASE 1
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status        = kStatus_SSS_Fail;
    sss_asymmetric_t ctx_asymm = {0};
    sss_object_t keyPair;
    size_t keylen          = KEY_BIT_LENGTH / 8;
    uint8_t digest[32]     = {0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
        0x12,
        0x13,
        0x14,
        0x15,
        0x16,
        0x17,
        0x18,
        0x19,
        0x1A,
        0x1B,
        0x1C,
        0x1D,
        0x1E,
        0x1F};
    size_t digestLen       = sizeof(digest);
    uint8_t signature[256] = {0};
    size_t signatureLen;

    LOG_I("Running Elliptic Curve Cryptography Example ex_sss_ecdaa.c");

    /* Pre-requisite for Signing Part*/
    status = sss_key_object_init(&keyPair, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(&keyPair,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Pair,
        kSSS_CipherType_EC_BARRETO_NAEHRIG,
        keylen,
        kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_store_generate_key(&pCtx->ks, &keyPair, KEY_BIT_LENGTH, 0);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    /* Asymmetric sign */
    status = sss_asymmetric_context_init(&ctx_asymm, &pCtx->session, &keyPair, kAlgorithm_SSS_ECDAA, kMode_SSS_Sign);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    signatureLen = sizeof(signature);
    /* Do Signing */
    LOG_I("Do Signing");
    LOG_MAU8_I("digest", digest, digestLen);
    status = sss_asymmetric_sign_digest(&ctx_asymm, digest, digestLen, signature, &signatureLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_MAU8_I("signature", signature, signatureLen);
    LOG_I("Signing Successful !!!");
    sss_asymmetric_context_free(&ctx_asymm);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_ecdaa Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_ecdaa Example Failed !!!...");
    }
    if (ctx_asymm.session != NULL)
        sss_asymmetric_context_free(&ctx_asymm);
    return status;
}
