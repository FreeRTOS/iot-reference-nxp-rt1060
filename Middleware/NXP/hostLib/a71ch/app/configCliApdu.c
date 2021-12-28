/**
 * @file configCliApdu.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling 'apdu' entry
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

// printf("    set [pair] -x <int> [-k <keyfile.pem> | -h <hexvalue_pub> -h <hexvalue_priv>]\n");
// printf("    set [pub]  -x <int> [-k <keyfile.pem> | -h <hexvalue>]\n");
// printf("    set [sym]  -x <int> -h <hexvalue>\n");
//  printf("    apdu -cmd <hexvalue> -sw <hexvalue>\n");

int a7xConfigCliCmdApdu(int argc, char **argv, U16 *sw)
{
    int nRet = AX_CLI_EXEC_FAILED;
    int argCurrent = 1;
    U8 cmd[256];
    U16 cmdLen = sizeof(cmd);
    U8 swHex[2];
    U16 swHexLen = sizeof(swHex);
    U16 swSoll;
    *sw = 0x0000;

    nRet = axCliGetHexString("cmd", "", cmd, &cmdLen, 4, 256, argc, argv, &argCurrent);
    if (nRet == AX_CLI_EXEC_OK)
    {
        nRet = axCliGetHexString("sw", "", swHex, &swHexLen, 2, 2, argc, argv, &argCurrent);
        if (nRet != AX_CLI_EXEC_OK)
        {
            return nRet;
        }
        else
        {
            if (swHexLen == 2)
            {
                swSoll = (swHex[0] << 8) + swHex[1];
                nRet = a7xConfigCmdApduSimple(cmd, cmdLen, swSoll, sw);
            }
            else
            {
                printf("Unexpected branch.\n");
                nRet = AX_CLI_API_ERROR;
            }
        }
    }

    return nRet;
}
