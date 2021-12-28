/**
* @file configCliWcrt.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2018 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* Command line handling 'wcrt' and 'ucrt' entries
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
#ifdef OPENSSL
#include <openssl/pem.h>
#endif

#include "axHostCrypto.h"
#include "tstHostCrypto.h"
#include "HLSEAPI.h"

// #define FLOW_VERBOSE_PROBE_A70

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

static HLSE_RET_CODE SetCertificateGpMemory(U16 crtIndex, U8 *certData, U16 crtDataLen, int writeCer, int extraBytes);
static int a7xConfigCmdWcrtGpFromfile(int index, char *szFilename, bool cerFile, int writeCer, int extraBytes, U16 *sw);

// printf("    wcrt -x <intvalue_index> [-c <certfile.crt> | -h <hexvalue_data> | -p <certfile.p12>]\n");
/**
* Config write certificate
*/
int a7xConfigCmdWcrt(U8 index, int update, U8 *crtData, U16 crtDataLen, int extraBytes, char *szFilename, int szFilenameLen, bool crtFile, U16 *sw) {
    int nRet = AX_CLI_EXEC_FAILED;
    HLSE_RET_CODE hlseRc;
    int writeCer = 0;

    if (update == 1) {
        writeCer = 1;
    }

    *sw = 0x0000;

    // Check Index
    if (index < 0 || index > 3) { return AX_CLI_ARG_VALUE_ERROR; }

    if (extraBytes < 0 || extraBytes > 127) { return AX_CLI_ARG_VALUE_ERROR; }

    if (crtDataLen > 0) {
        // Write data to GP memory
        hlseRc = SetCertificateGpMemory((U16)index, crtData, crtDataLen, writeCer, extraBytes);
        if (hlseRc == SW_OK)
        {
            *sw = 0x9000;
            nRet = AX_CLI_EXEC_OK;
        }
        else
        {
            *sw = hlseRc;
            nRet = AX_CLI_EXEC_FAILED;
        }
    }
    else if (szFilenameLen > 0) {
        nRet = a7xConfigCmdWcrtGpFromfile((U16)index, szFilename, crtFile, writeCer, extraBytes, sw);
    }
    else {
        return AX_CLI_ARG_VALUE_ERROR;
    }

    return nRet;
}

/**
* Set certificate data at GP memory
*/
static HLSE_RET_CODE SetCertificateGpMemory(U16 crtIndex, U8 *certData, U16 crtDataLen, int writeCer, int extraBytes) {
    HLSE_RET_CODE nRet = AX_CLI_EXEC_FAILED;
    HLSE_ATTRIBUTE attrUpdate;
    HLSE_OBJECT_HANDLE curHandle;
    HLSE_OBJECT_HANDLE updateHandle;
    HLSE_OBJECT_HANDLE certHandles[5];
    HLSE_OBJECT_INDEX index = crtIndex;
    HLSE_OBJECT_TYPE objType = HLSE_CERTIFICATE;
    HLSE_ATTRIBUTE attr_extra[3];
    U8 * extraByteBuffer = 0;
    int handleWasSet = 0;
    int totalLength = 0;
    int i;
    HLSE_RET_CODE hlseRc;
    unsigned short templateSize = 3;
    U16 certHandlesNum = sizeof(certHandles) / sizeof(HLSE_OBJECT_HANDLE);
    memset(certHandles, 0x00, sizeof(certHandles));
    curHandle = crtIndex;

    memset(certHandles, 0x00, sizeof(certHandles));

    // Create certificate object
    if (writeCer == 1) {
        totalLength = ((crtDataLen + 31) / 32 + extraBytes) * 32;
        extraByteBuffer = (U8 *)malloc(sizeof(U8) * ((crtDataLen + 31) / 32 + extraBytes) * 32);
        if (extraByteBuffer == 0)
        {
            return AX_CLI_DYN_ALLOC_ERROR;
        }
        memset(extraByteBuffer, 0x00, totalLength);
        memcpy(extraByteBuffer, certData, crtDataLen);

        attr_extra[0].type = HLSE_ATTR_OBJECT_TYPE;
        attr_extra[0].value = &objType;
        attr_extra[0].valueLen = sizeof(objType);
        attr_extra[1].type = HLSE_ATTR_OBJECT_INDEX;
        attr_extra[1].value = &index;
        attr_extra[1].valueLen = sizeof(index);
        attr_extra[2].type = HLSE_ATTR_OBJECT_VALUE;
        attr_extra[2].value = extraByteBuffer;
        attr_extra[2].valueLen = (U16)(crtDataLen + extraBytes);

        // Write certificate with extra bytes
        nRet = HLSE_CreateObject(attr_extra, templateSize, &certHandles[0]);
        if (extraByteBuffer) { free(extraByteBuffer); }

    }
    else {
        attrUpdate.type = HLSE_ATTR_OBJECT_VALUE;
        attrUpdate.value = certData;
        attrUpdate.valueLen = crtDataLen;

        // Find certificate handle
        // Enumerate handles
        certHandlesNum = sizeof(certHandles) / sizeof(HLSE_OBJECT_HANDLE);
        hlseRc = HLSE_EnumerateObjects(HLSE_CERTIFICATE, certHandles, &certHandlesNum);
        if (hlseRc != HLSE_SW_OK) { return AX_CLI_NO_OBJECTS; }

        // Find handle
        for (i = 0;i < certHandlesNum;i++) {
            if ((certHandles[i] & 0xF) == curHandle) {
                updateHandle = certHandles[i];
                handleWasSet = 1;
                break;
            }
        }
        if (!handleWasSet) { return AX_CLI_OBJECT_NOT_FOUND; }
        // Update certificate
        nRet = HLSE_SetObjectAttribute(updateHandle, &attrUpdate);
    }

    return nRet;
}

/**
* Get certificate from file
*/
static int a7xConfigCmdWcrtGpFromfile(int index, char *szFilename, bool cerFile, int writeCer, int extraBytes, U16 * sw)
{
    int error = AX_CLI_EXEC_FAILED;
    X509 *x;
    FILE *fp;
    HLSE_RET_CODE hlseRc;
    int len;
    unsigned char *buf;
    *sw = 0x0000;

    printf("Filename: %s\n", szFilename);
    fp = fopen(szFilename, "r");
    if (!fp)
    {
        printf("Unable to open the file: %s\n", szFilename);
        return AX_CLI_FILE_OPEN_FAILED;
    }

    if (cerFile) {
        x = d2i_X509_fp(fp, NULL);
    }
    else {

        x = PEM_read_X509(fp, NULL, NULL, NULL);
    }
    if (x == NULL)
    {
        printf("%s is not a valid pem file / certificate\n", szFilename);
        fclose(fp);
        return AX_CLI_FILE_PEM_READ_FAILED;
    }


    buf = NULL;
    len = i2d_X509(x, &buf);

    if (len < 0)
    {
        fclose(fp);
        return AX_CLI_PEM_CONVERT_FAILED;
    }
    else
    {
        printf("Certificate Size (DER format) = %d byte\n", len);

        // Write
        hlseRc = SetCertificateGpMemory((U16)index, buf, (U16)len, writeCer, extraBytes);
        free(buf);
        fclose(fp);
    }

    if (hlseRc == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
        *sw = 0x9000;
    }
    else
    {
        error = AX_CLI_EXEC_FAILED;
        *sw = hlseRc;
    }
    return error;
}
