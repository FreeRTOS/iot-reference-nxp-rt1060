/**
 * @file configCliRefpem.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling 'refpem' entry
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

#define DBG_A71CH_CONFIG_CLI_REFPEM

#ifdef DBG_A71CH_CONFIG_CLI_REFPEM
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

// refpem -c <hex_value> -x <int> [-k <keyfile.pem>] -r <ref_keyfile.pem>

int a7xConfigCliCmdRefpem(int argc, char **argv, U16 *sw)
{
    int nRet = AX_CLI_EXEC_FAILED;
    int argCurrent = 1;
    char szKeyFile[AX_FILENAME_MAX];
    char szRefKeyFile[AX_FILENAME_MAX];
    U8 storageClass;
    U16 storageClassLen = 1;
    int keyIndex;

    *sw = 0;

    // Do not go beyond the last argument when parsing
    if (argCurrent >= argc)
    {
        a7xConfigCliHelp("a71chConfig");
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    // Get secure storage class
    nRet = axCliGetHexString("c", "", &storageClass, &storageClassLen, 1, 1, argc, argv, &argCurrent);
    if (nRet != AX_CLI_EXEC_OK) { return nRet; }

    // Get Index
    nRet = axCliGetInteger("x", "", &keyIndex, 0, MAX_OBJECTS_NUM-1, argc, argv, &argCurrent);
    if (nRet != AX_CLI_EXEC_OK) { return nRet; }

    strcpy(szKeyFile, "");
    nRet = axCliGetOptionalString("k", "", szKeyFile, AX_FILENAME_MAX-1, argc, argv, &argCurrent);
    if ( (nRet == AX_CLI_EXEC_OK) || (nRet == AX_CLI_ARG_OPTION_ERROR) )
    {
        nRet = axCliGetString("r", "", szRefKeyFile, AX_FILENAME_MAX-1, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK) { return nRet; }
        nRet = a7xConfigCmdRefpem(storageClass, keyIndex, szKeyFile, szRefKeyFile, sw);
    }

    return nRet;
}
