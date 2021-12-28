/**
 * @file configCliInteractive.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling 'interactive' entry
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
#include "configCli.h"
#include "configCmd.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#define FLOW_VERBOSE_PROBE_A70

#ifdef FLOW_VERBOSE_PROBE_A70
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

// #define DBG_A71CH_CONFIG_CLI_INTERACTIVE

#ifdef DBG_A71CH_CONFIG_CLI_INTERACTIVE
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

static int fInteractiveMode = AX_INTERACTIVE_MODE_OFF;

int a7xConfigCliGetInteractiveMode()
{
    return fInteractiveMode;
}


int a7xConfigCliCmdInteractive(int argc, char **argv)
{
    int nRet = AX_CLI_EXEC_FAILED;
    char **myargv;
    int nTokens = 0;
    char szLine[AX_LINE_MAX];
#ifdef DBG_A71CH_CONFIG_CLI_INTERACTIVE
    int i = 0;
#endif

    AX_UNUSED_ARG(argc);
    AX_UNUSED_ARG(argv);

    fInteractiveMode = AX_INTERACTIVE_MODE_ON;

    printf(">>> ");
    while (fgets(szLine, AX_LINE_MAX, stdin) != NULL)
    {
        if (strncmp(szLine, "quit", 4) == 0) {
            nRet = AX_CLI_EXEC_OK;
            break;
        }
        nTokens = 0;
        if ((nRet = axMakeArgv(szLine, " \n", &myargv, &nTokens)) != AX_CLI_EXEC_OK) {
            fprintf(stderr, "Could not make argument array for %s\n", szLine);
            continue;
        }
#ifdef DBG_A71CH_CONFIG_CLI_INTERACTIVE
        printf("The argument array contains (%d tokens):\n", nTokens);
        for (i = 0; i < nTokens; i++) {
            printf("[%d]:%s\n", i, myargv[i]);
        }
#endif
        nRet = a7xConfigCli("interactive", nTokens, myargv);
        axFreeArgv(myargv);
        printf(">>> ");
    }

    fInteractiveMode = AX_INTERACTIVE_MODE_OFF;
    return nRet;
}
