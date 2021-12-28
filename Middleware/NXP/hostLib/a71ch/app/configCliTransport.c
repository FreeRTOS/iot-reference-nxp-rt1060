/**
 * @file configCliTransport.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling 'lock' entry
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

// #define DBG_PROBE_A70

#ifdef DBG_PROBE_A70
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

// printf("    transport lock\n");
// printf("    transport unlock -h <hexvalue_tpkey>\n");

int a7xConfigCliCmdTransport(int argc, char **argv, U16 *sw)
{
    int nRet = AX_CLI_EXEC_FAILED;
    int argCurrent = 1;
    U8 transportLock[24];
    U16 transportLockLen = sizeof(transportLock);
    *sw = 0x0000;

    // Do not go beyond the last argument when parsing
    if (argCurrent >= argc)
    {
        a7xConfigCliHelp("a71chConfig");
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    if (strcmp(argv[argCurrent], "lock") == 0) {
        nRet = a7xConfigCmdTransportLock(sw);
    }
    else if (strcmp(argv[argCurrent], "unlock") == 0) {
        argCurrent++;
        nRet = axCliGetHexString("h", "", transportLock, &transportLockLen, 16, 16, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        nRet = a7xConfigCmdTransportUnlock(transportLock, transportLockLen, sw);
    }
    else {
        printf("'%s' is an unknown command option.\n", argv[argCurrent]);
        return a7xConfigCliHelp("a71chConfig");
    }

    return nRet;
}
