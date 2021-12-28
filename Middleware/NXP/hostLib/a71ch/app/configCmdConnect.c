/**
 * @file configCmdConnect.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'connect'. Includes optional console handling
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
#include "configState.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

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
int a7xConfigCmdConnectClose(U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xCmdConnectClose();
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for info command. Can be called from GUI.
 */
U16 a7xCmdConnectClose()
{
    U16 sw;
    U8 mode = SMCOM_CLOSE_MODE_TERMINATE;

    sw = SM_Close(NULL, mode);

    return sw;
}

/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdConnectOpen(U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;
    const char *connectString = NULL;

#if defined(SMCOM_JRCP_V1)
    connectString = a7xConfigGetConnectString();
#endif

    *sw = a7xCmdConnectOpen(connectString);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for info command. Can be called from GUI.
 */
U16 a7xCmdConnectOpen(const char *connectString)
{
    U16 sw;
#if defined(TDA8029_UART) || defined(SCI2C) || defined(PCSC) || defined(SMCOM_JRCP_V1)
    U8 atr[64];
    U16 atrLen = sizeof(atr);
    SmCommState_t commState;
#endif

#if defined(TDA8029_UART) || defined(SCI2C) || defined(PCSC)
    AX_UNUSED_ARG(connectString);
    sw = SM_Connect(NULL, &commState, atr, &atrLen);
#elif defined(SMCOM_JRCP_V1)
    sw = SM_RjctConnect(NULL, connectString, &commState, atr, &atrLen);
#else
    sw = AX_CLI_NOT_IMPLEMENTED;
#endif

    return sw;
}
