/**
* @file configCliObj.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2018 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* Command line handling 'obj' entry
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

/**
* Allocate memory
*/
static int AllocateBufferObj(U8 ** buf, U16 * length, int argc, int argCurrent, char **argv) {
    // Do not go beyond the last argument when parsing
    if ((argCurrent + 1) >= argc)
    {
        return AX_CLI_ARG_COUNT_MISTAKE;
    }
    *length = (U16)strlen(argv[argCurrent + 1]);
    *length = ((*length) / 2) + 1;
    // Alloc
    *buf = (U8 *)malloc(sizeof(U8) * (*length));
    if (buf == 0)
    {
        return AX_CLI_DYN_ALLOC_ERROR;
    }

    return AX_CLI_EXEC_OK;
}

//
// \return Return 0 upon success
int a7xConfigCliCmdObj(int argc, char ** argv, U16 *sw)
{
    int argCurrent = 1;
    a71_ObjCmdClass_t ssc = A71_OBJ_UNDEF;
    int offset = 0;
    int bufLen = 0;
    int lineLen = 0;
    int nRet = 0;
    int index = 0;
    int chunkSize = 64;
    int readLength = 0;
    int segments = 0;
    U8 * objData= NULL;
    U16 objDataLen = 0;
    U8 offsetArray[4];
    U16 offsetArrayLen = sizeof(offsetArray);
    U8 readLengthArray[4];
    U16 readLengthArrayLen = sizeof(readLengthArray);
    char szFilename[MAX_FILE_PATH];
    char szLineSize[MAX_FILE_PATH];


    // Do not go beyond the last argument when parsing
    if (argCurrent >= argc)
    {
        a7xConfigCliHelp("a71chConfig");
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    if (strcmp(argv[argCurrent], "update") == 0) {
        ssc = A71_OBJ_UPDATE;
    }
    else if (strcmp(argv[argCurrent], "write") == 0) {
        ssc = A71_OBJ_WRITE;
    }
    else if (strcmp(argv[argCurrent], "get") == 0) {
        ssc = A71_OBJ_READ;
    }
    else if (strcmp(argv[argCurrent], "erase") == 0) {
        ssc = A71_OBJ_ERASE;
    }
    else {
        printf("%s is an unknown command option.\n", argv[argCurrent]);
        return a7xConfigCliHelp("a71chConfig");
    }
    argCurrent++;

    // Get Index
    nRet = axCliGetInteger("x", "", &index, 0, MAX_OBJECTS_NUM-1, argc, argv, &argCurrent);
    if (nRet != AX_CLI_EXEC_OK) { return nRet; }

    switch (ssc)
    {
    case A71_OBJ_WRITE:
        //obj create -x <int> [ -f <data.txt> | -h <hexvalue_data> | -n <segments> ]
        if (strcmp(argv[argCurrent], "-h") == 0) {
            // Allocate memory for input buffer
            nRet = AllocateBufferObj(&objData, &objDataLen, argc, argCurrent, argv);
            if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        }
        nRet = axCliGetHexString("h", "", objData, &objDataLen, 1, objDataLen, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) {
            if (nRet == AX_CLI_ARG_OPTION_ERROR) {
                szFilename[0] = 0;
                bufLen = sizeof(szFilename) - 1;
                nRet = axCliGetOptionalString("f", "", szFilename, bufLen, argc, argv, &argCurrent);
                if (nRet != AX_CLI_EXEC_OK) {
                    if (nRet == AX_CLI_ARG_OPTION_ERROR) {
                        nRet = axCliGetInteger("n", "", &segments, 0, 127, argc, argv, &argCurrent);
                        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
                        nRet = a7xConfigCmdWriteObjFromSegments(index, segments, sw);
                    }
                    else {
                        return nRet;
                    }
                }
                else {
                    // Read optional file line size
                    lineLen = sizeof(szLineSize) - 1;
                    nRet = axCliGetOptionalString("t", "", szLineSize, lineLen, argc, argv, &argCurrent);
                    if (nRet != AX_CLI_EXEC_OK) { chunkSize = 64; }
                    if (szFilename[0] == 0x0 && nRet == AX_CLI_EXEC_OK) {
                        return AX_CLI_ARG_COUNT_MISTAKE;
                    }
                    szLineSize[lineLen] = 0x0;
                    if (nRet == AX_CLI_EXEC_OK) {
                        if ((strcmp(szLineSize, "hex_16") == 0x0) || strcmp(szLineSize, "Hex_16") == 0x0) {
                            chunkSize = 32;
                        }
                        else if ((strcmp(szLineSize, "hex_32") != 0x0) && strcmp(szLineSize, "Hex_32") != 0x0) {
                            return AX_CLI_ARG_VALUE_ERROR;
                        }
                    }
                    nRet = a7xConfigCmdWriteObjFromfile(index, szFilename, chunkSize, A71_OBJ_WRITE, sw);
                    return nRet;
                }
            }
            else {
                return nRet;
            }
        }
        else {
            nRet = a7xConfigCmdWriteObj(index, objData, objDataLen, sw);
            if (objData) { free(objData); }
        }
        break;
    case A71_OBJ_UPDATE:
        // obj update -x <int> -h <hexvalue_offset> [-f <data.txt> -t [hex_16|hex_32] | -h <hexvalue_data>]
        nRet = axCliGetHexString("h", "", offsetArray, &offsetArrayLen, 2, 2, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        offset = (offsetArray[0] << 8) + (offsetArray[1]);
        if (strcmp(argv[argCurrent], "-h") == 0) {
            // Allocate memory for input buffer
            nRet = AllocateBufferObj(&objData, &objDataLen, argc, argCurrent, argv);
            if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        }
        nRet = axCliGetHexString("h", "", objData, &objDataLen, 1, 4096, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) {
            if (nRet == AX_CLI_ARG_OPTION_ERROR) {
                szFilename[0] = 0;
                bufLen = sizeof(szFilename) - 1;
                nRet = axCliGetString("f", "", szFilename, bufLen, argc, argv, &argCurrent);
                if (nRet != AX_CLI_EXEC_OK) { return nRet; }
                // Read optional file line size
                lineLen = sizeof(szLineSize) - 1;
                nRet = axCliGetOptionalString("t", "", szLineSize, lineLen, argc, argv, &argCurrent);
                if (nRet != AX_CLI_EXEC_OK) { chunkSize = 64; }
                if (szFilename[0] == 0x0 && nRet == AX_CLI_EXEC_OK) {
                    return AX_CLI_ARG_COUNT_MISTAKE;
                }
                szLineSize[lineLen] = 0x0;
                if (nRet == AX_CLI_EXEC_OK) {
                    if ((strcmp(szLineSize, "hex_16") == 0x0) || strcmp(szLineSize, "Hex_16") == 0x0) {
                        chunkSize = 32;
                    }
                    else if ((strcmp(szLineSize, "hex_32") != 0x0) && strcmp(szLineSize, "Hex_32") != 0x0) {
                        return AX_CLI_ARG_VALUE_ERROR;
                    }
                }
                nRet = a7xConfigCmdUpdateObjFromfile(index, offset, szFilename, chunkSize, A71_OBJ_UPDATE, sw);
                return nRet;
            }
        }
        else {
            nRet = a7xConfigCmdUpdateObj(index, offset, objData, objDataLen, sw);
            if (objData) { free(objData); }
        }
        break;
    case A71_OBJ_READ:
        // obj get -x <int> -h <hexvalue_offset> -s <int_size> [ -f <data.txt> ]
        // Read offset
        nRet = axCliGetHexString("h", "", offsetArray, &offsetArrayLen, 2, 2, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) {
            offset = 0x0;
        }
        else {
            offset = (offsetArray[0] << 8) + (offsetArray[1]);
        }
        // Read length of read
        nRet = axCliGetHexString("s", "", readLengthArray, &readLengthArrayLen, 2, 2, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) {
            readLength = 0;
        }
        else {
            readLength = (readLengthArray[0] << 8) + (readLengthArray[1]);
        }
        // Read optional file name
        bufLen = sizeof(szFilename) - 1;
        nRet = axCliGetOptionalString("f", "", szFilename, bufLen, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { memset(szFilename, 0x0, sizeof(szFilename)); }
        // Read optional file line size
        lineLen = sizeof(szLineSize) - 1;
        nRet = axCliGetOptionalString("t", "", szLineSize, lineLen, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { chunkSize = 64; }
        if (szFilename[0] == 0x0 && nRet == AX_CLI_EXEC_OK) {
            return AX_CLI_ARG_COUNT_MISTAKE;
        }
        szLineSize[lineLen] = 0x0;
        if (nRet == AX_CLI_EXEC_OK) {
            if ((strcmp(szLineSize, "hex_16") == 0x0) || strcmp(szLineSize, "Hex_16") == 0x0) {
                chunkSize = 32;
            }
            else if ((strcmp(szLineSize, "hex_32") != 0x0) && strcmp(szLineSize, "Hex_32") != 0x0) {
                return AX_CLI_ARG_VALUE_ERROR;
            }
        }
        // read data
        nRet = a7xConfigCmdReadObj(index, offset, readLength, chunkSize, szFilename, sw);
        break;

    case A71_OBJ_ERASE:
        // obj erase -x <int>
        nRet = a7xConfigCmdEraseObj(index, sw);
        break;

    default:
        // Cannot be triggered
        return AX_CLI_NOT_IMPLEMENTED;
    }

    return nRet;
}
