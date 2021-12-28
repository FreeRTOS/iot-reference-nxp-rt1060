/**
 * @file configCmdTransport.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'transport'. Includes optional console handling
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

#define FLOW_VERBOSE_PROBE_A70

#ifdef FLOW_VERBOSE_PROBE_A70
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

// #define DBG_PROBE_A70

#ifdef DBG_PROBE_A70
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdTransportLock(U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xConfigTransportLock();
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for transport lock command. Can be called from GUI.
 */
U16 a7xConfigTransportLock()
{
    U16 sw;

    sw = A71_LockModule();

    return sw;
}


/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdTransportUnlock(U8 *transportConfigKey, U16 transportConfigKeyLen, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xConfigTransportUnlock(transportConfigKey, transportConfigKeyLen);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for transport unlock command. Can be called from GUI.
 */
U16 a7xConfigTransportUnlock(U8 *transportConfigKey, U16 transportConfigKeyLen)
{
    U16 sw;
    S32 hcRet;
    U8 challenge[A71CH_MODULE_UNLOCK_CHALLENGE_LEN];
    U16 challengeLen = sizeof(challenge);
    U8 unlockCode[16];

    sw = A71_GetUnlockChallenge(challenge, &challengeLen);
    if (sw != SW_OK) {
        return sw;
    }

    // Decrypt challenge
    hcRet = HOST_AES_ECB_DECRYPT(unlockCode, challenge, transportConfigKey, transportConfigKeyLen);
    if (hcRet != HOST_CRYPTO_OK)
    {
        printf("HOST_AES_ECB_DECRYPT: failed.\n");
        return ERR_CRYPTO_ENGINE_FAILED;
    }

    sw = A71_UnlockModule(unlockCode, 16);

    return sw;
}
