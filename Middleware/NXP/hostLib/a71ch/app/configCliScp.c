/**
 * @file configCliScp.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling 'scp' entry
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

#define DBG_A71CH_CONFIG_CLI_SCP

#ifdef DBG_A71CH_CONFIG_CLI_SCP
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

// scp auth -h <keyversion> -k <keys>
// scp put  -h <keyversion> -k <keys>

// File Format
//
// # This is a comment, empty lines and comment lines allowed.
// ENC 00..FF # Trailing comment
// MAC 00..FF # Optional trailing comment
// DEK 00..FF # Optional trailing comment

int a7xConfigCliCmdScp(int argc, char **argv, U16 *sw)
{
    int nRet = AX_CLI_EXEC_FAILED;
    int argCurrent = 1;
    char szFile[AX_FILENAME_MAX];
    U8 keyVersion;
    U16 keyVersionLen = 1;
    ax_ScpCmdClass_t cmdClass = AX_SCP_CMD_UNDEF;

    *sw = 0;

    // Do not go beyond the last argument when parsing
    if (argCurrent >= argc)
    {
        a7xConfigCliHelp("a71chConfig");
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    if (strcmp(argv[argCurrent], "auth") == 0) {
        cmdClass = AX_SCP_CMD_AUTH;
    }
    else if (strcmp(argv[argCurrent], "put") == 0) {
        cmdClass = AX_SCP_CMD_PUT;
    }
    else if (strcmp(argv[argCurrent], "clear_host") == 0) {
        return a7xConfigCmdScpClearHost();
    }
    else {
        printf("%s is an unknown command option.\n", argv[argCurrent]);
        return a7xConfigCliHelp("a71chConfig");
    }
    argCurrent++;

    // Get keyVersion
    nRet = axCliGetHexString("h", "", &keyVersion, &keyVersionLen, 1, 1, argc, argv, &argCurrent);
    if (nRet != AX_CLI_EXEC_OK) { return nRet; }

    nRet = axCliGetString("k", "", szFile, AX_FILENAME_MAX, argc, argv, &argCurrent);
    if (nRet != AX_CLI_EXEC_OK) { return nRet; }

    nRet = a7xConfigCmdScpFromKeyfile(cmdClass, keyVersion, szFile, sw);

    return nRet;
}
