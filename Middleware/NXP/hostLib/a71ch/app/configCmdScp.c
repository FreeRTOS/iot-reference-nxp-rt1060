/**
 * @file configCmdScp.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'scp'. Includes optional console handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

// project specific include files
#include "sm_types.h"
#include "sm_apdu.h"
#include "tst_sm_util.h"
#include "tst_a71ch_util.h"
#include "probeAxUtil.h"
#include "configCmd.h"
#include "configCli.h"
#include "configState.h"
#include "a71_debug.h"
#include "ax_util.h"

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

#if 0
/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdSetEcc(a71_SecureStorageClass_t ssc, U8 index, eccKeyComponents_t *eccKc, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    *sw = a7xCmdSetEcc(ssc, index, eccKc);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
    }
    return error;
}

/**
 * API wrapper for set ecc (keypair/pub) command. Can be called from GUI.
 */
U16 a7xCmdSetEcc(a71_SecureStorageClass_t ssc, U8 index, eccKeyComponents_t *eccKc)
{
    U16 sw;

    switch (ssc)
    {
        case A71_SSC_KEY_PAIR:
            sw = A71_SetEccKeyPair(index, eccKc->pub, eccKc->pubLen, eccKc->priv, eccKc->privLen);
            break;

        case A71_SSC_PUBLIC_KEY:
            sw = A71_SetEccPublicKey(index, eccKc->pub, eccKc->pubLen);
            break;

        default:
            sw = A7X_CONFIG_STATUS_API_ERROR;
            break;
    }

    return sw;
}
#endif


/**
 * Clear the SCP03 state on the Host. As a result subsequent APDU commands will be
 * sent in the clear.
 */
int a7xConfigCmdScpClearHost()
{
    DEV_ClearChannelState();
    return a7xConfigSetHostScp03State(AX_SCP03_CHANNEL_OFF);
}


/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdScpFromKeyfile(ax_ScpCmdClass_t cmdClass, U8 keyVersion, char *szFilename, U16 *sw)
{
    U8 scp03Enc[AES_KEY_LEN_nBYTE];
    U8 scp03Mac[AES_KEY_LEN_nBYTE];
    U8 scp03Dek[AES_KEY_LEN_nBYTE];
    U8 *currentKeyDek = NULL;
    U8 sCounter[3];
    U16 sCounterLen = sizeof(sCounter);

    int error = AX_CLI_EXEC_FAILED;

    error = a7xConfigGetScpKeysFromKeyfile(scp03Enc, scp03Mac, scp03Dek, szFilename);
    if (error == AX_CLI_EXEC_OK)
    {
        error = AX_CLI_EXEC_FAILED;
        switch (cmdClass)
        {
            case AX_SCP_CMD_AUTH:
                *sw = SCP_Authenticate(scp03Enc, scp03Mac, scp03Dek, SCP_KEY_SIZE, sCounter, &sCounterLen);
                if (*sw == SW_OK)
                {
                    a7xConfigSetHostScp03State(AX_SCP03_CHANNEL_ON);
                    error = AX_CLI_EXEC_OK;
                }
                break;
            case AX_SCP_CMD_PUT:
                *sw = SCP_GP_PutKeys(keyVersion, scp03Enc, scp03Mac, scp03Dek, currentKeyDek, SCP_KEY_SIZE);
                if (*sw == SW_OK)
                {
                    error = AX_CLI_EXEC_OK;
                }
                break;
            default:
                error = AX_CLI_API_ERROR;
                break;
        }
    }
    return error;
}

/**
 * Get scp keys from keyfile. Can be called from GUI.
 */
int a7xConfigGetScpKeysFromKeyfile(U8 *enc, U8 *mac, U8 *dek, char *szKeyFile)
{
    int nRet = AX_CLI_EXEC_FAILED;
    U8 hexArray[AES_KEY_LEN_nBYTE];
    char szLine[AX_LINE_MAX];
    char keyToken[128];
    unsigned int idx;
    FILE *fHandle = NULL;
    int fEnc = 0;
    int fMac = 0;
    int fDek = 0;

    // Open the file
    fHandle = fopen(szKeyFile, "r");
    if (fHandle == NULL)
    {
        printf("Failed to open file %s for reading", szKeyFile);
        return AX_CLI_FILE_OPEN_FAILED;
    }

    while (fgets(szLine, AX_LINE_MAX, fHandle) != NULL)
    {
        DBGPRINTF("%s\n", szLine);
        // Filter out lines STARTING with the comment '#' sign
        for (idx=0; idx<strlen(szLine); idx++) {
            if (!isspace(szLine[idx])) {
                break;
            }
        }
        if (szLine[idx] == '#')  { continue; }
        // Remove all contents from the command line starting with '#'
        for (idx=0; idx<strlen(szLine); idx++) {
            if (szLine[idx] == '#') {
                szLine[idx] = '\0';
                break;
            }
        }

        nRet = axCliGetKeyFixedLenHexValueFromLine(keyToken, sizeof(keyToken), hexArray, sizeof(hexArray), szLine);

        if (nRet != AX_CLI_EXEC_OK) {
            break;
        }

        if (!strcmp(keyToken, "ENC")) {
            if (fEnc == 0) {
                memcpy(enc, hexArray, sizeof(hexArray));
                fEnc = 1;
            }
            else {
                // Duplicate key value
                nRet = AX_CLI_FILE_FORMAT_ERROR;
                break;
            }
        }
        else if (!strcmp(keyToken, "MAC")) {
            if (fMac == 0) {
                memcpy(mac, hexArray, sizeof(hexArray));
                fMac = 1;
            }
            else {
                // Duplicate key value
                nRet = AX_CLI_FILE_FORMAT_ERROR;
                break;
            }
        }
        else if (!strcmp(keyToken, "DEK")) {
            if (fDek == 0) {
                memcpy(dek, hexArray, sizeof(hexArray));
                fDek = 1;
            }
            else {
                // Duplicate key value
                nRet = AX_CLI_FILE_FORMAT_ERROR;
                break;
            }
        }
        else {
            printf("Unknown key name: %s\n", keyToken);
            nRet = AX_CLI_FILE_FORMAT_ERROR;
            break;
        }
    }
    fclose(fHandle);

    // Ensure we have a value for all keys
    if ( (nRet != AX_CLI_EXEC_OK) || (fEnc != 1) || (fMac != 1) || (fDek !=1 ) ) {
        nRet = AX_CLI_FILE_FORMAT_ERROR;
    }

    return nRet;
}
