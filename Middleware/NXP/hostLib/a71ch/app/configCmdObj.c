/**
* @file configCmdObj.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2018 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* Command handling for 'obj'. Includes optional console handling
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

// project specific include files
#include "sm_types.h"
#include "sm_apdu.h"
#include "tst_sm_util.h"
#include "tst_a71ch_util.h"
#include "probeAxUtil.h"
#include "configCmd.h"
#include "configCli.h"
#include "a71_debug.h"
#include "HLSEAPI.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#ifdef OPENSSL
#include <openssl/pem.h>
#endif

#define FLOW_VERBOSE_PROBE_A70

#ifdef FLOW_VERBOSE_PROBE_A70
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

// Warning: defining DBG_PROBE_A70 also exposes Private Key being set in log
// #define DBG_PROBE_A70

#ifdef DBG_PROBE_A70
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

/**
* a7xConfigCmdWriteObj - create object from hex data
*/
U16 a7xConfigCmdWriteObj(int index, U8 * objData, U16 objDataLen, U16 *sw) {
    HLSE_RET_CODE nRet = AX_CLI_EXEC_FAILED;
    HLSE_OBJECT_HANDLE objHandle;
    HLSE_OBJECT_TYPE objType = HLSE_DATA;
    unsigned short templateSize = 3;
    HLSE_ATTRIBUTE attr[3];

    attr[0].type = HLSE_ATTR_OBJECT_TYPE;
    attr[0].value = &objType;
    attr[0].valueLen = sizeof(objType);
    attr[1].type = HLSE_ATTR_OBJECT_INDEX;
    attr[1].value = &index;
    attr[1].valueLen = sizeof(index);
    attr[2].type = HLSE_ATTR_OBJECT_VALUE;
    attr[2].value = objData;
    attr[2].valueLen = objDataLen;

    nRet = HLSE_CreateObject(attr, templateSize, &objHandle);
    if (nRet != HLSE_SW_OK) {
        *sw = nRet;
        return AX_CLI_EXEC_FAILED;
    }
    else { *sw = 0x9000; }

    return AX_CLI_EXEC_OK;
}
/**
* a7xConfigCmdWriteObjFromSegments - create empty objects in size of n segments
*/
int a7xConfigCmdWriteObjFromSegments(int index, int segments, U16 *sw) {
    HLSE_RET_CODE nRet = AX_CLI_EXEC_FAILED;
    U8 * buffer = 0; // a buffer to hold the read data

    buffer = (U8 *)malloc(sizeof(U8) * (segments * 32) );
    memset(buffer, 0x0, segments * 32);

    nRet = a7xConfigCmdWriteObj(index, buffer, (U16)(segments * 32), sw);
    if (buffer) {free(buffer);}
    return nRet;
}

/**
* a7xConfigCmdWriteObjFromfile - create object from file
*/
static int SetObjectFromFile(int index, int offset, char *szFilename, int chunkSize, a71_ObjCmdClass_t cmdType, U16 *sw) {
    HLSE_RET_CODE nRet = AX_CLI_EXEC_FAILED;
    FILE *file;
    unsigned char *buffer;
    unsigned long fileLen;
    U8 byteArray[4096];
    int i = 0;
    int breakFromLoop = 0;
    int readIndex = 0;
    int bufSize = 0;
    *sw = 0x0000;

    if (chunkSize != 64 && chunkSize != 32) {
        return AX_CLI_ARG_RANGE_ERROR;
    }

    printf("Filename: %s\n", szFilename);
    file = fopen(szFilename, "r");
    if (!file)
    {
        printf("Unable to open the file: %s\n", szFilename);
        return AX_CLI_FILE_OPEN_FAILED;
    }

    //Get file length
    fseek(file, 0, SEEK_END);
    fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);

    //Allocate memory
    buffer = (unsigned char *)malloc(sizeof(unsigned char) * (fileLen * 2));
    if (!buffer)
    {
        fprintf(stderr, "Memory error!");
        fclose(file);
        return AX_CLI_DYN_ALLOC_ERROR;
    }

    //Read file contents into buffer
    for (i = 0;i < (signed)fileLen;i += chunkSize) {
        char tmp[10];
        int y;
        // Read the chunk size make sure it is valid data
        fread(buffer + i, chunkSize, 1, file);
        for (y = 0;y < chunkSize;y++) {
            if (!isxdigit(buffer[y + i]) && (buffer[y + i] < 'a' || buffer[y + i] > 'f' || buffer[y + i] < 'A' || buffer[y + i] > 'F')) {
                if (feof(file)) {
                    breakFromLoop = 1;
                    readIndex += y;
                    break;
                }
                else {
                    fclose(file);
                    return AX_CLI_FILE_FORMAT_ERROR;
                }
            }
        }
        if (breakFromLoop) {
            break;
        }
        // Now make sure this is the end of line size of chunk data
        fread(tmp, 1, 1, file);
        if (tmp[0] == '\r') {
            fread(tmp, 1, 1, file);
        }
        if (tmp[0] != '\n') {
            fclose(file);
            return AX_CLI_FILE_FORMAT_ERROR;
        }
        readIndex += chunkSize;
        // End of file exit reading loop
        if (feof(file)) {
            break;
        }
    }
    buffer[readIndex] = 0x0;
    fclose(file);
    bufSize = strlen((const char *)buffer);
    axConvertHexString2ByteArray(byteArray, (const char *)buffer, 0, bufSize / 2);

    switch (cmdType) {
    case A71_OBJ_WRITE:
        // Create object
        nRet = a7xConfigCmdWriteObj(index, (U8 *)byteArray, (U16)(bufSize / 2), sw);
        break;
    case A71_OBJ_UPDATE:
        // Create object
        nRet = (U16)a7xConfigCmdUpdateObj(index, offset, (U8 *)byteArray, (U16)(bufSize / 2), sw);
        break;
    default:
        return AX_CLI_ARG_VALUE_ERROR;
    };

    if (buffer) { free(buffer); }
    return nRet;
}
/**
* a7xConfigCmdWriteObjFromfile - create object from file
*/
int a7xConfigCmdWriteObjFromfile(int index, char *szFilename, int chunkSize, a71_ObjCmdClass_t cmdType, U16 *sw) {
    return SetObjectFromFile(index, 0, szFilename, chunkSize, cmdType, sw);
}

/**
* a7xConfigCmdUpdateObjFromfile - update object from file
*/
int a7xConfigCmdUpdateObjFromfile(int index, int offset, char *szFilename, int chunkSize, a71_ObjCmdClass_t cmdType, U16 *sw) {
    return SetObjectFromFile(index, offset, szFilename, chunkSize, cmdType, sw);
}

/**
* a7xConfigCmdUpdateObjFromfile - update object from hex data
*/
int a7xConfigCmdUpdateObj(int index, int offset, U8 * objData, U16 objDataLen, U16 *sw) {
    HLSE_RET_CODE nRet = AX_CLI_EXEC_FAILED;
    HLSE_ATTRIBUTE attr;
    HLSE_RET_CODE hlseRc;
    HLSE_OBJECT_HANDLE objHandles[5];
    HLSE_DIRECT_ACCESS_ATTRIBUTE_VALUE theValue;
    HLSE_OBJECT_HANDLE curHandle;
    HLSE_OBJECT_HANDLE objHandle;
    U16 objHandlesNum = sizeof(objHandles) / sizeof(HLSE_OBJECT_HANDLE);
    int handleWasSet = 0;
    int i;

    // Set curHandle
    curHandle = index;

    attr.type = HLSE_ATTR_DIRECT_ACCESS_OBJECT_VALUE;

    theValue.offset = (U16)offset;
    theValue.bytes = objDataLen;
    theValue.buffer = objData;
    theValue.bufferLen = objDataLen;

    attr.value = &theValue;
    attr.valueLen = sizeof(theValue);

    // Enumerate handles
    objHandlesNum = sizeof(objHandles) / sizeof(HLSE_OBJECT_HANDLE);
    hlseRc = HLSE_EnumerateObjects(HLSE_DATA, objHandles, &objHandlesNum);
    if (hlseRc != HLSE_SW_OK) { return AX_CLI_NO_OBJECTS; }

    // Find object handle
    // Find handle
    for (i = 0;i < 5;i++) {
        if ((objHandles[i] & 0xF) == curHandle) {
            objHandle = objHandles[i];
            handleWasSet = 1;
            break;
        }
    }
    if (!handleWasSet) { return AX_CLI_OBJECT_NOT_FOUND; }

    nRet = HLSE_SetObjectAttribute(objHandle, &attr);
    if (nRet != HLSE_SW_OK) {
        *sw = nRet;
        return AX_CLI_EXEC_FAILED;
    }
    else { *sw = 0x9000; }

    return AX_CLI_EXEC_OK;

}

/**
* a7xConfigCmdReadObj - read object data at offset
*/
int a7xConfigCmdReadObj(int index, int offset, int length, int chunkSize, char *szFilename, U16 *sw) {
    HLSE_RET_CODE nRet = AX_CLI_EXEC_FAILED;
    HLSE_ATTRIBUTE attr;
    int i;
    int curLength = 0;
    int writeLength = 0;
    HLSE_RET_CODE hlseRc;
    HLSE_DIRECT_ACCESS_ATTRIBUTE_VALUE theValue;
    HLSE_OBJECT_HANDLE objHandles[5];
    HLSE_OBJECT_HANDLE curHandle;
    HLSE_OBJECT_HANDLE readHandle;
    int handleWasSet = 0;
    U16 objHandlesNum = sizeof(objHandles) / sizeof(HLSE_OBJECT_HANDLE);
    U8 buffer[4096]; // a buffer to hold the read data
    char objData[4096];
    int objDataBufSize = sizeof(objData);
    FILE * pFile = NULL;
    int saveObj = 0;

    if (chunkSize != 64 && chunkSize != 32) {
        return AX_CLI_ARG_RANGE_ERROR;
    }

    // Check if we have file name
    if (szFilename[0] != 0x0) { saveObj = 1; }

    // Set curHandle
    curHandle = index;

    // Enumerate handles
    objHandlesNum = sizeof(objHandles) / sizeof(HLSE_OBJECT_HANDLE);
    hlseRc = HLSE_EnumerateObjects(HLSE_DATA, objHandles, &objHandlesNum);
    if (hlseRc != HLSE_SW_OK) { return AX_CLI_NO_OBJECTS; }

    // Find handle
    for (i = 0;i < objHandlesNum;i++) {
        if ((objHandles[i] & 0xF) == curHandle) {
            readHandle = objHandles[i];
            handleWasSet = 1;
            break;
        }
    }
    if (!handleWasSet) { return AX_CLI_OBJECT_NOT_FOUND; }

    if (length > 0) {
        attr.type = HLSE_ATTR_DIRECT_ACCESS_OBJECT_VALUE;
        theValue.offset = (U16)offset;
        theValue.bytes = (U16)length;
        theValue.buffer = buffer;
        theValue.bufferLen = sizeof(buffer);

        attr.value = &theValue;
        attr.valueLen = sizeof(theValue);
    }
    else {
        attr.type = HLSE_ATTR_OBJECT_VALUE;
        attr.value = buffer;
        attr.valueLen = sizeof(buffer);;
    }

    nRet = HLSE_GetObjectAttribute(readHandle, &attr);
    if (nRet != HLSE_SW_OK) {
        *sw = nRet;
        return AX_CLI_EXEC_FAILED;
    }
    else { *sw = 0x9000; }
    if (length > 0) {
        axPrintByteArray("OBJ_DATA", (U8*)theValue.buffer, theValue.bufferLen, AX_COMPACT_32);
        writeLength = curLength = theValue.bufferLen;
    }
    else {
        axPrintByteArray("OBJ_DATA", (U8*)attr.value, attr.valueLen, AX_COMPACT_32);
        writeLength = curLength = attr.valueLen;
    }

    // Create file according to the user file path
    if (saveObj) {
        if (length > 0) {
            axConvertByteArray2HexString(objData, objDataBufSize, theValue.buffer, theValue.bufferLen, AX_COMPACT_LINE);
        }
        else {
            axConvertByteArray2HexString(objData, objDataBufSize, attr.value, attr.valueLen, AX_COMPACT_LINE);
        }
        pFile = fopen(szFilename, "w");
        writeLength = writeLength * 2;
        if (pFile) {
            for (i = 0;i < curLength * 2;i += chunkSize) {
                if (writeLength < chunkSize) {
                    fwrite(objData + i, writeLength, 1, pFile);
                    writeLength -= writeLength;
                }
                else {
                    fwrite(objData + i, chunkSize, 1, pFile);
                    writeLength -= chunkSize;
                }
                if ((i + chunkSize) < curLength*2) {
                    fwrite("\n", sizeof(char), 1, pFile);
                }
            }
            fclose(pFile);
        }
        else {
            return AX_CLI_EXEC_FAILED;
        }

    }

    return AX_CLI_EXEC_OK;
}

/**
* a7xConfigCmdEraseObj - erase object at index x
*/
int a7xConfigCmdEraseObj(int index, U16 *sw) {
    int i;
    HLSE_RET_CODE hlseRc;
    HLSE_OBJECT_HANDLE objHandles[5];
    HLSE_OBJECT_HANDLE curHandle;
    HLSE_OBJECT_HANDLE eraseHandle;
    int handleWasSet = 0;
    U16 objHandlesNum = sizeof(objHandles) / sizeof(HLSE_OBJECT_HANDLE);

    *sw = 0x0000;

    memset(objHandles, 0x00, sizeof(objHandles));

    // Get Index
    curHandle = index;

    // Enumerate handles
    objHandlesNum = sizeof(objHandles) / sizeof(HLSE_OBJECT_HANDLE);
    hlseRc = HLSE_EnumerateObjects(HLSE_DATA, objHandles, &objHandlesNum);
    if (hlseRc != HLSE_SW_OK) { return AX_CLI_NO_OBJECTS; }

    // Find handle
    for (i = 0;i < objHandlesNum;i++) {
        if ((objHandles[i] & 0xF) == curHandle) {
            eraseHandle = objHandles[i];
            handleWasSet = 1;
            break;
        }
    }
    if (!handleWasSet) { return AX_CLI_OBJECT_NOT_FOUND; }

    // Erase
    hlseRc = HLSE_EraseObject(eraseHandle);
    if (hlseRc != HLSE_SW_OK) {
        *sw = hlseRc;
        return AX_CLI_EXEC_FAILED;
    }
    else { *sw = 0x9000; }

    return AX_CLI_EXEC_OK;
}
