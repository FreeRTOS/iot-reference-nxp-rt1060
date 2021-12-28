/**
 * @file configCliScript.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling 'script' entry
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

#ifdef DBG_A71CH_CONFIG_CLI_SCRIPT
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif


int a7xConfigCliCmdScript(int argc, char ** argv)
{
    int nRet = AX_CLI_EXEC_FAILED;
    char **myargv;
    int nTokens = 0;
    char szLine[AX_LINE_MAX];
#ifdef DBG_A71CH_CONFIG_CLI_SCRIPT
    int i = 0;
#endif
    int argCurrent = 1;
    char szFile[AX_FILENAME_MAX];
    FILE *fHandle = NULL;
    unsigned int idx;

    nRet = axCliGetString("f", "", szFile, AX_FILENAME_MAX, argc, argv, &argCurrent);
    if (nRet != AX_CLI_EXEC_OK) { return nRet; }

    // Open the file
    fHandle = fopen(szFile, "r");
    if (fHandle == NULL)
    {
        printf("Failed to open file %s for reading", szFile);
        return AX_CLI_FILE_OPEN_FAILED;
    }

    while (fgets(szLine, AX_LINE_MAX, fHandle) != NULL)
    {
        printf(">> %s\n", szLine);
        if (strncmp(szLine, "quit", 4) == 0) { break; }
        // Filter out lines STARTING with the comment '#' sign
        for (idx=0; idx<strlen(szLine); idx++) {
            if (!isspace(szLine[idx])) {
                break;
            }
        }
        if (szLine[idx] == '#')  { continue; }
        // Remove all contents from the command line starting with '#'
        for (idx=0; idx<strlen(szLine); idx++) {
            if (szLine[idx] == '#') {
                szLine[idx] = '\0';
                break;
            }
        }
        // Deal with command line
        nTokens = 0;
        if ((nRet = axMakeArgv(szLine, " \r\n", &myargv, &nTokens)) != AX_CLI_EXEC_OK) {
            fprintf(stderr, "Could not make argument array for %s\n", szLine);
            continue;
        }
#ifdef DBG_A71CH_CONFIG_CLI_SCRIPT
        printf("The argument array contains (%d tokens):\n", nTokens);
        for (i = 0; i < nTokens; i++) {
            printf("[%d]:%s\n", i, myargv[i]);
        }
#endif
        nRet = a7xConfigCli("interactive", nTokens, myargv);
        axFreeArgv(myargv);
        // Don't handle next commands in case an error occurs.
        if (nRet != AX_CLI_EXEC_OK) {
            break;
        }
    }

    fclose(fHandle);

    return nRet;
}
