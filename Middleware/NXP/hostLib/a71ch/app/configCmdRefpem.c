/**
 * @file configCmdRefpem.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'refpem'.
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
#include "axEccRefPem.h"
#include "probeAxUtil.h"
#include "configCmd.h"
#include "configCli.h"
#include "a71_debug.h"

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

// #define DBG_PROBE_A70

#ifdef DBG_PROBE_A70
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif


/**
 * A hook for the command line handler to create a reference key
 */
int a7xConfigCmdRefpem(U8 storageClass, U8 keyIndex, const char *szKeyFile, const char *szRefKeyFile, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;
    eccKeyComponents_t eccKc;

    eccKc.bits = 256;
    eccKc.curve = ECCCurve_NIST_P256;
    eccKc.privLen = 0;
    eccKc.pubLen = 0;

    if (!strcmp(szKeyFile, ""))
    {
        DBGPRINTF("a7xConfigCmdRefpem: Retrieve public key from security module.\n");
        // No key file was provided on command line, retrieve public key from module
        error = AX_CLI_EXEC_OK;
        eccKc.pubLen = 0;
    }
    else
    {
        DBGPRINTF("a7xConfigCmdRefpem: Keyfile %s provided on command line.\n", szKeyFile);
        error = a7xConfigGetEccKcFromPemfile(&eccKc, (a71_SecureStorageClass_t) storageClass, szKeyFile);
        if (error != AX_CLI_EXEC_OK)
        {
            return error;
        }
    }

    *sw = axEccWritePemRefKey(storageClass, keyIndex, szRefKeyFile, eccKc.pub, eccKc.pubLen);
    if (*sw != SW_OK)
    {
        printf("axEccWritePemRefKey failed with 0x%04X.\n", *sw);
        return AX_CLI_FILE_PEM_WRITE_FAILED;
    }

    return error;
}
