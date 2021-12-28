/**
 * @file configCmdApdu.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'apdu'. Includes optional console handling
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
int a7xConfigCmdApduSimple(U8 *cmd, U16 cmdLen, U16 swExpected, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;
    U8 rsp[256];
    U16 rspLen = sizeof(rsp);
    U16 sndRcvStatus = 0;

    sndRcvStatus = a7xCmdApdu(cmd, cmdLen, rsp, &rspLen);
    if (sndRcvStatus == SW_OK)
    {
        // Extract status code from response
        if (rspLen >= 2)
        {
            *sw = (rsp[rspLen-2] << 8) + rsp[rspLen-1];
            if (*sw == swExpected)
            {
                error = AX_CLI_EXEC_OK;
            }
        }
        else
        {
            // Else branch can not occur
            *sw = 0;
        }
        a7xCmdApduPrettyPrint(cmd, cmdLen, rsp, rspLen);
    }
    else
    {
        *sw = 0;
    }
    return error;
}

int a7xCmdApduPrettyPrint(U8 *cmd, U16 cmdLen, U8 *rsp, U16 rspLen)
{
    axPrintByteArray("cmd", cmd, cmdLen, AX_COMPACT_32);
    axPrintByteArray("rsp", rsp, rspLen, AX_COMPACT_32);
    return AX_CLI_EXEC_OK;
}


/**
 * API wrapper for apdu command. Can be called from GUI.
 */
U16 a7xCmdApdu(U8 *cmd, U16 cmdLen, U8 *rsp, U16 *rspLen)
{
    U16 sw;

    sw = SM_SendAPDU(cmd, cmdLen, rsp, rspLen);

    return sw;
}
