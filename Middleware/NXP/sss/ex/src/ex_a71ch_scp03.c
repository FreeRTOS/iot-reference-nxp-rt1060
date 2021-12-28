/*
 *
 * Copyright 2018-2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "ex_a71ch_scp03.h"

#include <fsl_sss_sscp.h>
#include <nxEnsure.h>
#include <stdio.h>

#include "ex_sss_boot_int.h"
#include "nxLog_App.h"

#if SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

/**
* Fetch random data from A71CH and use as SCP03 static keys
*
* @param[in,out] keyEnc IN: Buffer to contain key; OUT: Key created
* @param[in,out] keyMac IN: Buffer to contain key; OUT: Key created
* @param[in,out] keyDek IN: Buffer to contain key; OUT: Key created
*/
sss_status_t ex_a71ch_FetchRandomScp03Keys(U8 *keyEnc, U8 *keyMac, U8 *keyDek)
{
    U16 sw                      = 0;
    U8 random[3 * SCP_KEY_SIZE] = {0};
    U8 randomLen                = (U8)sizeof(random);
    sss_status_t status         = kStatus_SSS_Fail;

    // Validate input parameters
    ENSURE_OR_GO_CLEANUP(keyEnc != NULL);
    ENSURE_OR_GO_CLEANUP(keyMac != NULL);
    ENSURE_OR_GO_CLEANUP(keyDek != NULL);

    LOG_I("Clear host-side SCP03 channel state");
    DEV_ClearChannelState();

    LOG_I("ex_a71ch_FetchRandomScp03Keys() - Enter");
    // Security module generates random data for initial SCP03 keys
    sw = A71_GetRandom(random, randomLen);
    // AX_CHECK_SW(sw, SW_OK, "Failed to fetch random data");

    // Storing Static Keys
    memcpy(keyEnc, random, SCP_KEY_SIZE);
    memcpy(keyMac, random + SCP_KEY_SIZE, SCP_KEY_SIZE);
    memcpy(keyDek, random + (2 * SCP_KEY_SIZE), SCP_KEY_SIZE);

cleanup:
    status = ((sw == SW_OK) ? kStatus_SSS_Success : kStatus_SSS_Fail);
    LOG_I("ex_a71ch_FetchRandomScp03Keys() - Leave, result = %s", ((status == kStatus_SSS_Success) ? "OK" : "FAILED"));
    return status;
}

/**
* Set SCP03 static keys in the A71CH.
*
* @param[in,out] keyEnc IN: Buffer to contain key; OUT: Key created and inserted into A71CH
* @param[in,out] keyMac IN: Buffer to contain key; OUT: Key created and inserted into A71CH
* @param[in,out] keyDek IN: Buffer to contain key; OUT: Key created and inserted into A71CH
*
* @pre SCP03 static keys have not been set. Either A71CH is a fresh production sample or it has
* been forced into the initial state through the DBG Interface.
* NOTE-1: The function DBG_RESET is not available in production samples
* NOTE-2: Static SCP03 keys can only be set once
*/
sss_status_t ex_a71ch_SetSeScp03Keys(U8 *keyEnc, U8 *keyMac, U8 *keyDek)
{
    U16 sw              = 0;
    U8 *currentKeyDek   = NULL;
    U8 keyVersion       = 1;
    sss_status_t status = kStatus_SSS_Fail;

    // Validate input parameters
    ENSURE_OR_GO_CLEANUP(keyEnc != NULL);
    ENSURE_OR_GO_CLEANUP(keyMac != NULL);
    ENSURE_OR_GO_CLEANUP(keyDek != NULL);

    LOG_I("Clear host-side SCP03 channel state");
    DEV_ClearChannelState();

    LOG_I("ex_a71ch_SetSeScp03Keys() - Enter");
    LOG_I("Provision the SCP03 keys - secure element side - with key-data");

    keyVersion = (U8)(SST_HOST_SCP_KEYSET >> 8);
    LOG_I("SCP_GP_PutKeys(keyVersion=0x%02)", keyVersion);
    sw = SCP_GP_PutKeys(keyVersion, keyEnc, keyMac, keyDek, currentKeyDek, AES_KEY_LEN_nBYTE);
    // AX_CHECK_SW(sw, SW_OK, "Failed to set SCP03 keys");

cleanup:
    status = ((sw == SW_OK) ? kStatus_SSS_Success : kStatus_SSS_Fail);
    LOG_I("ex_a71ch_SetSeScp03Keys() - Leave, result = %s", ((status == kStatus_SSS_Success) ? "OK" : "FAILED"));
    return status;
}

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

#endif
