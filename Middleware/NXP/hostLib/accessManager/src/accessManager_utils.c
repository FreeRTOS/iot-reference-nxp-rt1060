/**
* @file accessManager_com.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2016,2020 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* This file implements basic communication functionality between Host and
* Secure element.
* @par History
*
*****************************************************************************/
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "nxLog_App.h"
#include "accessManager_com.h"

#if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)

#include "ex_a71ch_scp03.h"
#include "sm_apdu.h"
#include <ctype.h>

int a71chMakeArgv(const char *s, const char *delimiters, char ***argvp, int *argc)
{
    int i;
    int nToken;
    const char *sStart;
    char *szCopy;

    if (argc == NULL) {
        return -1;
    }
    *argc = 0;

    if ((s == NULL) || (delimiters == NULL) || (argvp == NULL))
    {
        return -1;
    }
    *argvp = NULL;
    sStart = s + strspn(s, delimiters);
    if ((szCopy = (char *)malloc(strlen(sStart) + 1)) == NULL)
    {
        return -1;
    }
    strcpy(szCopy, sStart);
    nToken = 0;

    // Count the number of tokens in a first run through
    if (strtok(szCopy, delimiters) != NULL)
    {
        for (nToken = 1; strtok(NULL, delimiters) != NULL; nToken++) ;
    }

    // Create argument array for ptrs to the tokens
    if ((*argvp = (char **)malloc((nToken + 1)*sizeof(char *))) == NULL)
    {
        free(szCopy);
        return -1;
    }

    // Insert pointers to tokens into the argument array, they point to segments of the
    // allocated string (szCopy)
    if (nToken == 0)
    {
        free(szCopy);
    }
    else
    {
        strcpy(szCopy, sStart);
        **argvp = strtok(szCopy, delimiters);
        for (i = 1; i < nToken; i++)
        {
            *((*argvp) + i) = strtok(NULL, delimiters);
        }
    }
    // Close pointer array with a final NULL pointer
    *((*argvp) + nToken) = NULL;
    *argc = nToken;
    return 0;
}

void a71chFreeArgv(char **argv)
{
   if (argv == NULL) { return; }
   if (*argv != NULL) { free(*argv); }
   free(argv);
}

int a71chConvertHexString2ByteArray(U8 *byteArray, const char *string, int nOffset, int nByte)
{
    char szDummy[] = "szDummy";
    char *pastConverted = szDummy; // Catch number conversion issues
    int j;

    for (j=0; j<nByte; j++) {
        char byteAsString[3];
        byteAsString[0] = string[nOffset+2*j];
        byteAsString[1] = string[nOffset+2*j + 1];
        byteAsString[2] = '\0';
        byteArray[j] = (U8)(strtoul(byteAsString, &pastConverted, 16));

        if (pastConverted == byteAsString) {
            // Conversion failed
            printf("(%s/%d) %s can not be converted to HEX value.\r\n", __FILE__, __LINE__, byteAsString);
            return 1;
        }

    }
    return 0;
}

U16 a71chGetKeyFixedLenHexValueFromLine(char *key, int keyBufSize, U8 *hex, U16 hexLen, const char *szLine)
{
    U16 ret = ERR_GENERAL_ERROR;
    int nTokens = 0;
    char **myargv;
    int nLen = 0;
    int nRet = 0;

    nRet = a71chMakeArgv(szLine, " \r\n", &myargv, &nTokens);
    if (nRet != 0) {
        LOG_I("Could not make argument array for %s\n", szLine);
        goto exit;
    }

    if (nTokens == 2) {
        if ( (int)strlen(myargv[0]) < keyBufSize) {
            strcpy(key, myargv[0]);
            if ( (nLen = (int)strlen(myargv[1])) == (hexLen << 1)) {
                if ( a71chConvertHexString2ByteArray(hex, myargv[1], 0, hexLen) != 0 ) {
                    LOG_I("ASCII-Hex-String %s cannot be converted to hex array.\n", myargv[1]);
                    goto exit;
                }
            }
            else {
                LOG_I("ASCII-Hex-String %s wrong size.\n", myargv[1]);
                goto exit;
            }
        }
    }
    else {
        LOG_I("Cannot handle input line: wrong number of tokens: %d\n", nTokens);
        LOG_I("token[0]: %s\n", myargv[0]);
        LOG_I("token[1]: %s\n", myargv[1]);
        goto exit;
    }

    a71chFreeArgv(myargv);

    ret = SW_OK;
exit:
    return ret;
}


/**
 * Get scp keys from keyfile.
 */
#define AX_LINE_MAX 1024
U16 a71chGetScpKeysFromKeyfile(U8 *enc, U8 *mac, U8 *dek, char *szKeyFile)
{
    U16 ret = ERR_GENERAL_ERROR;
    U16 ret1  = 0;
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
        goto exit;
    }

    while (fgets(szLine, AX_LINE_MAX, fHandle) != NULL)
    {
        LOG_D("%s\n", szLine);
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

        ret1 = a71chGetKeyFixedLenHexValueFromLine(keyToken, sizeof(keyToken), hexArray, sizeof(hexArray), szLine);
        if (ret1 != SW_OK) {
            goto exit;
        }

        if (!strcmp(keyToken, "ENC")) {
            if (fEnc == 0) {
                memcpy(enc, hexArray, sizeof(hexArray));
                fEnc = 1;
            }
            else {
                // Duplicate key value
                goto exit;
            }
        }
        else if (!strcmp(keyToken, "MAC")) {
            if (fMac == 0) {
                memcpy(mac, hexArray, sizeof(hexArray));
                fMac = 1;
            }
            else {
                // Duplicate key value
                goto exit;
            }
        }
        else if (!strcmp(keyToken, "DEK")) {
            if (fDek == 0) {
                memcpy(dek, hexArray, sizeof(hexArray));
                fDek = 1;
            }
            else {
                // Duplicate key value
                goto exit;
            }
        }
        else {
            printf("Unknown key name: %s\n", keyToken);
            goto exit;
        }
    }

    // Ensure we have a value for all keys
    if ( (fEnc != 1) || (fMac != 1) || (fDek !=1 ) ) {
        goto exit;
    }

    ret = SW_OK;
exit:
    if (fHandle != NULL){
        fclose(fHandle);
    }
    return ret;
}

#endif //#if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)