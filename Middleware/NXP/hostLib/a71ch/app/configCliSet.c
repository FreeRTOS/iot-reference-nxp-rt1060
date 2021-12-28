/**
 * @file configCliSet.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling 'set' entry
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

int a7xConfigCmdCheckWrapping(U8 * key, U16 * keyLen, int argc, char **argv, int * argCurrent) {
    int nRet;
    U8 wrapKey[32];
    U16 wrapKeyLen = sizeof(wrapKey);
    U8 wrappedKey[72];
    U16 wrappedKeyLen = sizeof(wrappedKey);
    U16 ret = 0;
    nRet = 0;
    nRet = axCliGetHexString("w", "", wrapKey, &wrapKeyLen, 16, 32, argc, argv, argCurrent);
    if (nRet != AX_CLI_EXEC_OK) { wrapKeyLen = 0; }
    if (wrapKeyLen != 0) {
        if (*keyLen == 65) { // public key
            ret = HOSTCRYPTO_AesWrapKeyRFC3394(wrapKey, wrapKeyLen, wrappedKey, &wrappedKeyLen,
                key+1, (*keyLen)-1);
        }
        else {
            ret = HOSTCRYPTO_AesWrapKeyRFC3394(wrapKey, wrapKeyLen, wrappedKey, &wrappedKeyLen,
                key, *keyLen);
        }
        if (ret == SW_OK) {
            *keyLen = wrappedKeyLen;
            memcpy(key, wrappedKey, wrappedKeyLen);
        }
        else {
            return AX_CLI_WRAP_ERROR;
        }
    }

    return AX_CLI_EXEC_OK;
}

// printf("    set cnt  -x <int> -h <hexvalue>\n");
// printf("    set gp -h <hexvalue_offset:....> -h <hexvalue_data>\n");
// printf("    set gp -h <hexvalue_offset:....> -c <certfile.pem>\n");
// printf("    set pair -x <int> [-k <keyfile.pem> | -h <hexvalue_pub> -h <hexvalue_priv>]\n");
// printf("    set pub  -x <int> [-k <keyfile.pem> | -h <hexvalue>]\n");
// printf("    set sym  -x <int> -h <hexvalue>\n");

int a7xConfigCliCmdSet(int argc, char **argv, U16 *sw)
{
    int nRet = AX_CLI_EXEC_FAILED;
    int argCurrent = 1;
    int index = 0;
    U8 offsetArray[4];
    U16 offsetArrayLen = sizeof(offsetArray);
    U16 offset = 0;
    U8 gpData[32];
    U16 gpDataLen = sizeof(gpData);
    eccKeyComponents_t eccKcTls;
    U8 cnt[4];
    U16 cntLen = sizeof(cnt);
    U8 symSecret[24+8]; // + 8 for wrapping
    U16 symSecretLen = sizeof(symSecret);
    U8 configKey[24+8]; // + 8 for wrapping
    U16 configKeyLen = sizeof(configKey);
    a71_SecureStorageClass_t ssc = A71_SSC_UNDEF;
    *sw = 0x0000;

    // Initialize eccKeyPair
    eccKcTls.bits = 256;
    eccKcTls.curve = ECCCurve_NIST_P256;
    eccKcTls.privLen = 0;
    eccKcTls.pubLen = 0;

    // Do not go beyond the last argument when parsing
    if (argCurrent >= argc)
    {
        a7xConfigCliHelp("a71chConfig");
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    if (strcmp(argv[argCurrent], "cfg") == 0) {
        ssc = A71_SSC_CONFIG_KEY;
    }
    else if (strcmp(argv[argCurrent], "cnt") == 0) {
        ssc = A71_SSC_COUNTER;
    }
    else if (strcmp(argv[argCurrent], "gp") == 0) {
        ssc = A71_SSC_GP_DATA;
    }
    else if (strcmp(argv[argCurrent], "pair") == 0) {
        ssc = A71_SSC_KEY_PAIR;
    }
    else if (strcmp(argv[argCurrent], "pub") == 0) {
        ssc = A71_SSC_PUBLIC_KEY;
    }
    else if (strcmp(argv[argCurrent], "sym") == 0) {
        ssc = A71_SSC_SYM_KEY;
    }
    else {
        printf("%s is an unknown command option.\n", argv[argCurrent]);
        return a7xConfigCliHelp("a71chConfig");
    }
    argCurrent++;

    if (ssc == A71_SSC_GP_DATA) {
        nRet = axCliGetHexString("h", "", offsetArray, &offsetArrayLen, 2, 2, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        offset = (offsetArray[0] << 8) + (offsetArray[1]);
    }
    else
    {
        // Get Index
        nRet = axCliGetInteger("x", "", &index, 0, MAX_OBJECTS_NUM-1, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
    }

    switch (ssc)
    {
    case A71_SSC_GP_DATA:
        nRet = axCliGetHexString("h", "", gpData, &gpDataLen, 1, 32, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) {
            if (nRet == AX_CLI_ARG_OPTION_ERROR) {
                char szFilename[MAX_FILE_PATH];
                int bufLen = sizeof(szFilename) - 1;
                nRet = axCliGetString("c", "", szFilename, bufLen, argc, argv, &argCurrent);
                if (nRet != AX_CLI_EXEC_OK) { return nRet; }
                nRet = a7xConfigCmdSetGpFromPemfile(offset, szFilename, sw);
                return nRet;
            }
            else {
                return nRet;
            }
        }
        else {
            nRet = a7xConfigCmdSetGp(offset, gpData, gpDataLen, sw);
        }
        break;

    case A71_SSC_KEY_PAIR:
        nRet = axCliGetHexString("h", "", eccKcTls.pub, &(eccKcTls.pubLen), 65, 65, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) {
            if (nRet == AX_CLI_ARG_OPTION_ERROR) {
                char szFilename[MAX_FILE_PATH];
                int bufLen = sizeof(szFilename) - 1;
                nRet = axCliGetString("k", "", szFilename, bufLen, argc, argv, &argCurrent);
                if (nRet != AX_CLI_EXEC_OK) { return nRet; }
                nRet = a7xConfigCmdSetEccFromPemfile(ssc, (U8)index, szFilename, argc, argv, &argCurrent, sw);
                return nRet;
            }
            else {
                return nRet;
            }
        }
        // Both plain and wrapped private keys are accepted
        nRet = axCliGetHexString("h", "", eccKcTls.priv, &(eccKcTls.privLen), 32, 40, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        // Check if wrapping should take place
        nRet = a7xConfigCmdCheckWrapping(eccKcTls.priv, &eccKcTls.privLen, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        // Set key
        nRet = a7xConfigCmdSetEcc(ssc, (U8)index, &eccKcTls, sw);
        break;

    case A71_SSC_PUBLIC_KEY:
        // Both plain and wrapped keys are accepted (please check APDU spec for wrapping approach)
        nRet = axCliGetHexString("h", "", eccKcTls.pub, &(eccKcTls.pubLen), 65, 72, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) {
            if (nRet == AX_CLI_ARG_OPTION_ERROR) {
                char szFilename[MAX_FILE_PATH];
                int bufLen = sizeof(szFilename) - 1;
                nRet = axCliGetString("k", "", szFilename, bufLen, argc, argv, &argCurrent);
                if (nRet != AX_CLI_EXEC_OK) { return nRet; }
                nRet = a7xConfigCmdSetEccFromPemfile(ssc, (U8)index, szFilename, argc, argv, &argCurrent, sw);
                return nRet;
            }
            else {
                return nRet;
            }
        }
        // Check if wrapping should take place
        nRet = a7xConfigCmdCheckWrapping(eccKcTls.pub, &eccKcTls.pubLen, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        // Set key
        nRet = a7xConfigCmdSetEcc(ssc, (U8)index, &eccKcTls, sw);
        break;

    case A71_SSC_COUNTER:
        nRet = axCliGetHexString("h", "", cnt, &(cntLen), 4, 4, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        nRet = a7xConfigCmdSetCnt((U8)index, cnt, cntLen, sw);
        break;

    case A71_SSC_SYM_KEY:
        // Both plain and wrapped keys are accepted
        nRet = axCliGetHexString("h", "", symSecret, &(symSecretLen), 16, 24, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        // Check if wrapping should take place
        nRet = a7xConfigCmdCheckWrapping(symSecret, &symSecretLen, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        // Set key
        nRet = a7xConfigCmdSetSym((U8)index, symSecret, symSecretLen, sw);
        break;

    case A71_SSC_CONFIG_KEY:
        // Both plain and wrapped keys are accepted
        nRet = axCliGetHexString("h", "", configKey, &(configKeyLen), 16, 24, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        // Check if wrapping should take place
        nRet = a7xConfigCmdCheckWrapping(configKey, &configKeyLen, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        // Set key
        nRet = a7xConfigCmdSetConfigKey((U8)index, configKey, configKeyLen, sw);
        break;

    default:
        // Cannot be triggered
        return AX_CLI_NOT_IMPLEMENTED;
    }

    return nRet;
}
