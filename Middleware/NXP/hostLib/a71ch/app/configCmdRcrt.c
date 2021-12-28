/**
* @file configCliRcrt.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2018 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* Command line handling 'rcrt' entry
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


/**
* Config write certificate
*/
int a7xConfigCmdRcrt(U8 index, char *szFilename, int szFilenameLen, U16 *sw) {
    int i;
    U8 * cerData = NULL;
    HLSE_RET_CODE hlseRc;
    U16 selectResponse = 0;
    U8 debugOn = 0;
    U8 restrictedKpIdx = 0;
    U8 transportLockState = 0;
    U8 scpState = 0;
    U8 injectLockState = 0;
    U16 gpStorageSize = 0;
    U16 lReturn;
    HLSE_ATTRIBUTE attr;
    HLSE_OBJECT_HANDLE certHandles[MAX_CERT_HANDLE];
    HLSE_OBJECT_HANDLE curHandle;
    HLSE_OBJECT_HANDLE readHandle;
    int handleWasSet = 0;
    int saveCert = 0;
    FILE * pFile = NULL;
    U16 certHandlesNum = sizeof(certHandles) / sizeof(HLSE_OBJECT_HANDLE);

    *sw = 0x0000;

    // Check Index
    if (index < 0 || index > MAX_OBJECTS_NUM-1) { return AX_CLI_ARG_VALUE_ERROR; }

    memset(certHandles, 0x00, sizeof(certHandles));

    // Set index
    curHandle = index;

    // Check if we have file name
    if (szFilenameLen > 0) { saveCert = 1; }

    // Enumerate handles
    certHandlesNum = sizeof(certHandles) / sizeof(HLSE_OBJECT_HANDLE);
    hlseRc = HLSE_EnumerateObjects(HLSE_CERTIFICATE , certHandles, &certHandlesNum);
    if (hlseRc != HLSE_SW_OK) { return AX_CLI_NO_OBJECTS; }

    // Find handle
    for (i = 0;i < certHandlesNum;i++) {
        // printf("Looking at index %d: 0x%02X <> 0x%02X\n", i, (certHandles[i] & 0xF), curHandle);
        if ( (certHandles[i] & 0xF) == curHandle) {
            readHandle = certHandles[i];
            handleWasSet = 1;
            break;
        }
    }
    if (!handleWasSet) { return AX_CLI_OBJECT_NOT_FOUND; }

    // Allocate data ==> size of GP storage size
    lReturn = A71_GetModuleInfo(&selectResponse, &debugOn, &restrictedKpIdx, &transportLockState, &scpState, &injectLockState, &gpStorageSize);
    if (lReturn != SW_OK) { return AX_CLI_EXEC_FAILED; }
    cerData = (U8 *)malloc(sizeof(U8) * (gpStorageSize));
    if (cerData == 0)
    {
        return AX_CLI_DYN_ALLOC_ERROR;
    }

    // Read
    attr.type = HLSE_ATTR_OBJECT_VALUE;
    attr.value = cerData;
    attr.valueLen = gpStorageSize;
    hlseRc = HLSE_GetObjectAttribute(readHandle, &attr);
    if (hlseRc != HLSE_SW_OK) {
        *sw = hlseRc;
        if (cerData) {
            free(cerData);
        }
        return AX_CLI_EXEC_FAILED;
    }
    else { *sw = 0x9000; }
    axPrintByteArray("CER_DATA", (U8*)attr.value, attr.valueLen, AX_COMPACT_32);

    // Create file according to the user file path
    if (saveCert) {
        pFile = fopen(szFilename, "wb");
        if (pFile) {
            fwrite(attr.value, attr.valueLen, 1, pFile);
            fclose(pFile);
        }
        else {
            if (cerData) { free(cerData); }
            return AX_CLI_WRITE_CER_FILE_ERROR;
        }
    }

    // Free memory
    if (cerData) { free(cerData); }
    return AX_CLI_EXEC_OK;
}
