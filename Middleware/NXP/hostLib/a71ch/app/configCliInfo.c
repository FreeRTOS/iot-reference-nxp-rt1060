/**
 * @file configCliInfo.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling 'info' entry
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

//
// \return Return 0 upon success
int a7xConfigCliCmdInfo(int argc, char ** argv, U16 *sw)
{
    int argCurrent = 1;
    a71_SecureStorageClass_t ssc = A71_SSC_UNDEF;
    U8 offsetArray[4];
    U16 offsetArrayLen = sizeof(offsetArray);
    U16 offset = 0;
    int nSegments = 0;
    int nRet = 0;

        // Do not go beyond the last argument when parsing
    if (argCurrent >= argc)
    {
        a7xConfigCliHelp("a71chConfig");
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    if (strcmp(argv[argCurrent], "pair") == 0) {
        ssc = A71_SSC_KEY_PAIR;
    }
    else if (strcmp(argv[argCurrent], "pub") == 0) {
        ssc = A71_SSC_PUBLIC_KEY;
    }
    else if (strcmp(argv[argCurrent], "objects") == 0) {
        ssc = A71_SSC_OBJECTS;
    }
    else if (strcmp(argv[argCurrent], "sym") == 0) {
        ssc = A71_SSC_SYM_KEY;
    }
    else if (strcmp(argv[argCurrent], "cnt") == 0) {
        ssc = A71_SSC_COUNTER;
    }
    else if (strcmp(argv[argCurrent], "gp") == 0) {
        ssc = A71_SSC_GP_DATA;
        argCurrent++;
        nRet = axCliGetHexString("h", "", offsetArray, &offsetArrayLen, 2, 2, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        offset = (offsetArray[0] << 8) + (offsetArray[1]);
        nRet = axCliGetInteger("n", "", &nSegments, 1, 192, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
    }
    else if (strcmp(argv[argCurrent], "all") == 0) {
        ssc = A71_SSC_ALL;
    }
    else if (strcmp(argv[argCurrent], "device") == 0) {
        ssc = A71_SSC_MODULE;
    }
    else if (strcmp(argv[argCurrent], "status") == 0) {
        return a7xConfigCmdInfoStatus(sw);
    }
    else {
        printf("%s is an unknown command option.\n", argv[argCurrent]);
        return a7xConfigCliHelp("a71chConfig");
    }

    return a7xConfigCmdInfo(ssc, offset, nSegments, sw);
}
