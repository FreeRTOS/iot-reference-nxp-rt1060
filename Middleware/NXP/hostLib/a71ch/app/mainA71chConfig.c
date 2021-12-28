/****************************************************************************
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 *   Name: mainA71chConfig.c
 *
 *   Description:
 *     This file contains main entry for the A71CH configuration application.
 *
 ****************************************************************************/

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#ifdef _WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include "app_boot.h"
#include "ax_api.h"
#include "sm_apdu.h"
#include "configCli.h"
#include "configState.h"

#include "axHostCrypto.h"
#include "sm_timer.h"
#include "sm_printf.h"

#include "global_platf.h"

#define EX_APP_VERSION "1.20"

/*******************************************************************************
 **   Main Function  main()
 *******************************************************************************/
int main(int argc, char ** argv)
{
    U16 connectStatus = 0;
    // U8 Atr[64];
    // U16 AtrLen = sizeof(Atr);
    SmCommState_t commState;
    int expectedMinArg = 0;
    int nRet = 0;

#ifdef TDA8029_UART
    Scp03SessionState_t sessionState;
#endif

    nRet = app_boot_Init();
    sm_initSleep();

    sm_printf(DBGOUT, "a71chConfig (Rev %s) .. ", EX_APP_VERSION);
#if defined(SMCOM_JRCP_V1) || defined(SMCOM_JRCP_V2)
    expectedMinArg = 3;
#elif defined(RJCT_VCOM)
    expectedMinArg = 3;
#else
    expectedMinArg = 2;
#endif
    // <Begin-Hack: Commands that don't require any interaction with the secure element can be preceded with 'nc' (not connected)>
    if (argc >= expectedMinArg)
    {
        char *cmdName;
        char **cmdArg;
        int argcReduction = 0;

        cmdName = argv[0];

#if defined(SMCOM_JRCP_V1) || defined(SMCOM_JRCP_V2)
        argcReduction = 2;
#elif defined(RJCT_VCOM)
        argcReduction = 2;
#else
        argcReduction = 1;
#endif
        cmdArg = &argv[argcReduction];
        if ( (strcmp(cmdArg[0], "nc") == 0 )  )
        {
            argc -= argcReduction;
            if (argc > 0)
            {
                a7xConfigSetConnectString(argv[1]);
                sm_printf(DBGOUT, "NOT connecting to A71CH.\n");
                // Strip "nc"
                cmdArg = &argv[argcReduction+1];
                argc -= 1;
                nRet = a7xConfigCli(cmdName, argc, cmdArg);
                return nRet;
            }
            else
            {
                sm_printf(DBGOUT, "No command is following \'nc\' directive.\n");
                return AX_CLI_CHECK_USAGE;
            }
        }
    }

    // <End-Hack: Commands that don't require any interaction with the secure element>
    sm_printf(DBGOUT, "connect to A71CH. Chunksize at link layer = %d.\n", MAX_CHUNK_LENGTH_LINK);
    connectStatus = app_boot_Connect(&commState, argv[1]);

    if ( connectStatus == SW_FILE_NOT_FOUND )
    {
        sm_printf(CONSOLE, "SM_Connect failed with status 0x%04X\n", connectStatus);
        // <Begin-Hack: In case an identify or cplc is requested, don't return with an error>
        if (argc >= expectedMinArg)
        {
            char *cmdName;
            char **cmdArg;

            cmdName = argv[0];
#if defined(SMCOM_JRCP_V1) || defined(SMCOM_JRCP_V2)
            cmdArg = &argv[2];
            argc -= 2;
#elif defined(RJCT_VCOM)
            cmdArg = &argv[2];
            argc -= 2;
#else
            cmdArg = &argv[1];
            argc -= 1;
#endif
            if ( (strcmp(cmdArg[0], "identify") == 0 ) || (strcmp(cmdArg[0], "cplc") == 0 ) )
            {
                nRet = a7xConfigCli(cmdName, argc, cmdArg);
                return nRet;
            }
        }
        // <End-Hack: In case an identify is requested, don't return with an error>
        return AX_CLI_ERR_SELECT_FAILS;
    }
    else if (connectStatus != 0)
    {
        sm_printf(CONSOLE, "Select failed. SW = 0x%04X\n", connectStatus);
        return AX_CLI_ERR_SELECT_FAILS;
    }
    else
    {
        // int i=0;
#if defined(SCI2C)
        sm_printf(CONSOLE, "SCI2C_"); // To highlight the ATR format for SCI2C deviates from ISO7816-3
#endif

        sm_printf(CONSOLE, "HostLib Version            : 0x%04X\n", commState.hostLibVersion);
        sm_printf(CONSOLE, "Applet-Rev:SecureBox-Rev   : 0x%04X:0x%04X\n",
            commState.appletVersion, commState.sbVersion);
    }

    // Deal with extra argument when going through card server
    if (argc >= expectedMinArg)
    {
        char *cmdName;
        char **cmdArg;

        cmdName = argv[0];
#if defined(SMCOM_JRCP_V1) || defined(SMCOM_JRCP_V2)
        cmdArg = &argv[2];
        argc -= 2;
#elif defined(RJCT_VCOM)
        cmdArg = &argv[2];
        argc -= 2;
#else
        cmdArg = &argv[1];
        argc -= 1;
#endif
        nRet = a7xConfigCli(cmdName, argc, cmdArg);
    }
    else
    {
        nRet = a7xConfigCliHelp("a71chConfig");
    }

    return nRet;
}
