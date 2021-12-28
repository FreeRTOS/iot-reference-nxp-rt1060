/**
* @file configCliGet.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2018 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* Command line handling 'get' entry
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
int a7xConfigCliCmdGet(int argc, char ** argv, U16 *sw)
{
    int argCurrent = 1;
    int nRet = 0;
    int index = 0;
    int type = 0;
    int bufLen = 0;
    U8 offsetArray[2];
    U16 offsetArrayLen = sizeof(offsetArray);

    // Do not go beyond the last argument when parsing
    if (argCurrent >= argc)
    {
        a7xConfigCliHelp("a71chConfig");
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    if (strcmp(argv[argCurrent], "pub") == 0) {
        char szFilename[MAX_FILE_PATH];
        argCurrent++;
        // get type
        nRet = axCliGetHexString("c", "", offsetArray, &offsetArrayLen, 1, 1, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        type = offsetArray[0];
        if (type != 0x10 && type != 0x20) {
            return AX_CLI_ARG_RANGE_ERROR;
        }
        // Get Index
        nRet = axCliGetInteger("x", "", &index, 0, MAX_OBJECTS_NUM-1, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        // Get file name
        bufLen = sizeof(szFilename) - 1;
        nRet = axCliGetString("k", "", szFilename, bufLen, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        // read data
        nRet = a7xConfigCmdGetPub(index, type, szFilename, sw);
    }
    else {
        printf("%s is an unknown command option.\n", argv[argCurrent]);
        return a7xConfigCliHelp("a71chConfig");
    }

    return nRet;
}
