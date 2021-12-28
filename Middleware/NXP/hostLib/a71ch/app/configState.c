/**
 * @file configState.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Storing state of configure tool
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
#include "configState.h"
#include "a71_debug.h"

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

static U8 hostScp03State = AX_SCP03_CHANNEL_OFF;
static char szConnectString[256];

/**
 * hostScp03State setter
 */
int a7xConfigSetHostScp03State(U8 state)
{
    int error = AX_CLI_API_ERROR;

    switch (state)
    {
    case AX_SCP03_CHANNEL_OFF:
    case AX_SCP03_CHANNEL_ON:
        hostScp03State = state;
        error = AX_CLI_EXEC_OK;
        break;

    default:
        DBGPRINTF("a7xConfigSetHostScp03State: unknown state value\n");
        hostScp03State = AX_SCP03_CHANNEL_ILLEGAL;
        break;
    }

    return error;
}


/**
 * hostScp03State getter
 */
U8 a7xConfigGetHostScp03State()
{
    return hostScp03State;
}

/**
 * connect string setter. Currently the connect string is the ip address and
 * port number of the RJCT server to connect to (i.e. <IP-ADDRESS>:<NR>) passed
 * as a text string on the command line
 */
int a7xConfigSetConnectString(const char *szString)
{
    int nChar2Copy = 0;
    if ( strlen(szString) >= sizeof(szConnectString) )
    {
        nChar2Copy = sizeof(szConnectString) - 1;
    }
    else
    {
        nChar2Copy = strlen(szString);
    }
    strncpy(szConnectString, szString, nChar2Copy);
    return AX_CLI_EXEC_OK;
}

const char *a7xConfigGetConnectString()
{
    return szConnectString;
}
