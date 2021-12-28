/**
 * @file configCmdErase.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'erase'. Includes optional console handling
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
int a7xConfigCmdEraseCredential(a71_SecureStorageClass_t ssc, U8 index, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xConfigEraseCredential(ssc, index);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for erase (keypair/pub/sym/cnt) command. Can be called from GUI.
 */
U16 a7xConfigEraseCredential(a71_SecureStorageClass_t ssc, U8 index)
{
    U16 sw;

    switch (ssc)
    {
        case A71_SSC_KEY_PAIR:
            sw = A71_EraseEccKeyPair(index);
            break;

        case A71_SSC_PUBLIC_KEY:
            sw = A71_EraseEccPublicKey(index);
            break;

        case A71_SSC_SYM_KEY:
            sw = A71_EraseSymKey(index);
            break;

        case A71_SSC_COUNTER:
            sw = A71_DbgEraseCounter(index);
            break;

        default:
            sw = A7X_CONFIG_STATUS_API_ERROR;
            break;
    }

    return sw;
}
