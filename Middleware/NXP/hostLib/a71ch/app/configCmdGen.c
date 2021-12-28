/**
 * @file configCmdGen.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'gen'. Includes optional console handling
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
int a7xConfigCmdGen(U8 index, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xCmdGenEcc(index);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}


/**
 * API wrapper for gen ecc keypair command. Can be called from GUI.
 */
U16 a7xCmdGenEcc(U8 index)
{
    U16 sw;

    sw = A71_GenerateEccKeyPair(index);
    return sw;
}
