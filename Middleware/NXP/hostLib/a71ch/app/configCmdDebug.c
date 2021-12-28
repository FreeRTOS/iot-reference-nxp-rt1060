/**
 * @file configCmdDebug.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'debug'. Includes optional console handling
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
#include "HLSEAPI.h"

#define FLOW_VERBOSE_PROBE_A70

#ifdef FLOW_VERBOSE_PROBE_A70
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

#define DBG_PROBE_A70

#ifdef DBG_PROBE_A70
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdDebugReset()
{
    int error = AX_CLI_EXEC_FAILED;
    U16 sw;

    sw = a7xCmdDebugReset();
    if (sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for info command. Can be called from GUI.
 */
U16 a7xCmdDebugReset()
{
    U16 sw;
    int result = 1;

    //sw = A71_DbgReset();
    sw = HLSE_DbgReset();
    result &= AX_CHECK_SW(sw, SW_OK, "Failed to reset module");

    return sw;
}

/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdDebugDisable(U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xCmdDebugDisable();
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for info command. Can be called from GUI.
 */
U16 a7xCmdDebugDisable()
{
    U16 sw;
    int result = 1;

    sw = A71_DbgDisableDebug();
    result &= AX_CHECK_SW(sw, SW_OK, "Failed to disable debug mode of module");

    return sw;
}
