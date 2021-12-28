/**
* @file configCliEcrt.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2018 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* Command line handling 'ecrt' entry
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
#include "HLSEAPI.h"


// #define FLOW_VERBOSE_PROBE_A70
#define MAX_CERT_HANDLE 128

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

// printf("    wcrt -x <intvalue_index> [-c <certfile.crt> | -h <hexvalue_data> | -p <certfile.p12>]\n");
/**
* Config write certificate
*/
int a7xConfigCliCmdEcrt(int argc, char **argv, U16 *sw) {
    int nRet = AX_CLI_EXEC_FAILED;
    int argCurrent = 1;
    int index = 0;
    int i;
    HLSE_RET_CODE hlseRc;
    HLSE_OBJECT_HANDLE certHandles[MAX_CERT_HANDLE];
    HLSE_OBJECT_HANDLE curHandle;
    HLSE_OBJECT_HANDLE eraseHandle;
    int handleWasSet = 0;
    U16 certHandlesNum = sizeof(certHandles) / sizeof(HLSE_OBJECT_HANDLE);

    *sw = 0x0000;


    memset(certHandles, 0x00, sizeof(certHandles));

    // Do not go beyond the last argument when parsing
    if (argCurrent >= argc)
    {
        a7xConfigCliHelp("a71chConfig");
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    // Get Index
    nRet = axCliGetInteger("x", "", &index, 0, MAX_OBJECTS_NUM-1, argc, argv, &argCurrent);
    if (nRet != AX_CLI_EXEC_OK) { return nRet; }
    curHandle = index;

    // Enumerate handles
    certHandlesNum = sizeof(certHandles) / sizeof(HLSE_OBJECT_HANDLE);
    hlseRc = HLSE_EnumerateObjects(HLSE_CERTIFICATE, certHandles, &certHandlesNum);
    if (hlseRc != HLSE_SW_OK) { return AX_CLI_NO_OBJECTS; }

    // Find handle
    for (i = 0;i < certHandlesNum;i++) {
        if ((certHandles[i] & 0xF) == curHandle) {
            eraseHandle = certHandles[i];
            handleWasSet = 1;
            break;
        }
    }
    if (!handleWasSet) { return AX_CLI_OBJECT_NOT_FOUND; }

    // Erase
    hlseRc = HLSE_EraseObject(eraseHandle);
    if (hlseRc != HLSE_SW_OK) {
        *sw = hlseRc;
        return AX_CLI_ERASE_CER_FILE_ERROR;
    }
    else { *sw = 0x9000; }

    return AX_CLI_EXEC_OK;
}
