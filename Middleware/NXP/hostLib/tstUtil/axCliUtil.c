/**
 * @file axCliUtil.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Implementation of command line utility functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// project specific include files
#include "sm_types.h"
// #include "sm_apdu.h"
#include "axCliUtil.h"
#include "tst_sm_util.h"

#define FLOW_VERBOSE_PROBE_A70

#ifdef FLOW_VERBOSE_PROBE_A70
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

// #define DBG_AX_CLI_UTIL

#ifdef DBG_AX_CLI_UTIL
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

#define AX_CLI_GET_MODE_OPTIONAL  0
#define AX_CLI_GET_MODE_STRICT    1

#define CMD_HANDLER_MAX 20
#define CMD_NAME_MAX 64

typedef int (*a7xCmdHandler_t) (int argc, char ** argv);

typedef struct {
    char szName[CMD_NAME_MAX];
    a7xCmdHandler_t cmdHandler;
} a7xCmd_t;

int a7xAddCmd(char *szName, a7xCmdHandler_t cmdHandler);
int a7xRemoveCmd(char *szName);

static int nCmd = 0;
static a7xCmd_t a7xCmd[CMD_HANDLER_MAX];
static int axCliGetString_Internal(char *szShortOption, char *szLongOption, char *szString, int bufLen, int argc, char ** argv, int *argCurrent, int mode);

int a7xAddCmd(char *szName, a7xCmdHandler_t cmdHandler)
{
    if (nCmd == CMD_HANDLER_MAX)
    {
        return -1;
    }

    if (strlen(szName) >= (CMD_NAME_MAX-1) )
    {
        return -1;
    }

    strcpy(a7xCmd[nCmd].szName, szName);
    a7xCmd[nCmd].cmdHandler = cmdHandler;
    nCmd++;
    return 0;
}

char *axGetErrorString(int errorCode)
{
    switch(errorCode)
    {
    case AX_CLI_EXEC_OK:
        return "exec ok";
    case AX_CLI_EXEC_FAILED:
        return "exec failed";
    case AX_CLI_ERR_IP_ADR_MISSING:
        return "err ip adr missing";
    case AX_CLI_ERR_CANNOT_CONNECT:
        return "err cannot connect";
    case AX_CLI_ERR_SELECT_FAILS:
        return "err select fails";
    case AX_CLI_NOT_IMPLEMENTED:
        return "not implemented";
    case AX_CLI_CHECK_USAGE:
        return "check usage";
    case AX_CLI_PEM_CONVERT_FAILED:
        return "pem covert failed";
    case AX_CLI_FILE_OPEN_FAILED:
        return "file open failed";
    case AX_CLI_FILE_PEM_READ_FAILED:
        return "pemfile read failed";
    case AX_CLI_FILE_PEM_WRITE_FAILED:
        return "pemfile write failed";
    case AX_CLI_BIT_CURVE_ERROR:
        return "bit curve error";
    case AX_CLI_DYN_ALLOC_ERROR:
        return "dyn alloc error";
    case AX_CLI_EXEC_HALTED:
        return "exec halted";
    case AX_CLI_FILE_FORMAT_ERROR:
        return "file format error";
    case AX_CLI_ARG_RANGE_ERROR:
        return "arg range error";
    case AX_CLI_ARG_NAME_ERROR:
        return "arg name error";
    case AX_CLI_ARG_OPTION_ERROR:
        return "arg option error";
    case AX_CLI_ARG_COUNT_MISTAKE:
        return "arg count mistake";
    case AX_CLI_ARG_VALUE_ERROR:
        return "arg value error";
    case AX_CLI_BUFFER_SIZE_ERROR:
        return "buffer size error";
    case AX_CLI_API_ERROR:
        return "api error";
    case AX_CLI_WRAP_ERROR:
        return "wrap error";
    case AX_CLI_NO_OBJECTS:
        return "enumeration no object found error";
    case AX_CLI_OBJECT_NOT_FOUND:
        return "object at index not found error";
    case AX_CLI_WRITE_CER_FILE_ERROR:
        return "write certificate file error";
    case AX_CLI_ERASE_CER_FILE_ERROR:
        return "erase certificate file error";
    case AX_CLI_UPDATE_CER_FILE_ERROR:
        return "update certificate file error";
    default:
        return "unknown";
    }
}

/**
* Extract an integer value from argument array in case of matching option
* \pre argCurrent points to correct position (argument option to be handled)
* \post argCurrent points to next argument option to be handled.
*
* \note szLongOption not yet supported
*
* @param[in] szShortOption  Name of option (excluding '-' character)
* @param[in] szLongOption
* @param[in,out] value Integer value to be retrieved (must be a base 10 number)
* @param[in] minVal Minimum value (values outside range cause a ::AX_CLI_ARG_RANGE_ERROR return value)
* @param[in] maxVal Maximum value (values outside range cause a ::AX_CLI_ARG_RANGE_ERROR return value)
* @param[in] argc maximum amount of arguments passed as argument
* @param[in] argv argument array
* @param[in,out] argCurrent IN: Current argument; OUT: Next argument position (or end of array)
*
* @retval ::AX_CLI_EXEC_OK Upon successful execution
*/
int axCliGetInteger(char *szShortOption, char *szLongOption, int *value, int minVal, int maxVal, int argc, char ** argv, int *argCurrent)
{
    long longTmp = 0L;
    char szDummy[] = "szDummy";
    char *pastConverted = szDummy; // Catch number conversion issues
    char szShort[64];

    // Do not go beyond the last argument when parsing
    if ((*argCurrent + 1) >= argc)
    {
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    // Long option not yet supported
    if (strcmp(szLongOption, "") != 0)
    {
        return AX_CLI_NOT_IMPLEMENTED;
    }

    szShort[0] = '-';
    strcpy(&szShort[1], szShortOption);

    if (strcmp(argv[*argCurrent], szShort) == 0) {
        longTmp = strtol(argv[*argCurrent+1], &pastConverted, 10);
        if (pastConverted == argv[*argCurrent+1]) {
            // Conversion failed
            printf("%s %s: %s is not an integer\n", szShort, argv[*argCurrent+1], argv[*argCurrent+1]);
            return AX_CLI_ARG_VALUE_ERROR;
        }
        else {
            if (longTmp < minVal) { return AX_CLI_ARG_RANGE_ERROR; }
            if (longTmp > maxVal) { return AX_CLI_ARG_RANGE_ERROR; }
            *value = (int)longTmp;
            DBGPRINTF("axCliGetInteger: %s option with %d\n", szShort, *value);
        }
    }
    else {
        printf("Argument %s not expected\n", argv[*argCurrent]);
        return AX_CLI_ARG_OPTION_ERROR;
    }

    // Upon success.
    (*argCurrent) += 2;
    return AX_CLI_EXEC_OK;
}

/**
* Extract a hexadecimal (ASCII) string from argument array in case of matching option,
* store it as a binary array
* \pre argCurrent points to correct position (argument option to be handled)
* \post argCurrent points to next argument option to be handled.
*
* \note szLongOption not yet supported
*
* @param[in] szShortOption  Name of option (excluding '-' character)
* @param[in] szLongOption  Pointer to the provided hash (or any other bytestring).
* @param[in,out] hex IN: Buffer to contain hex value; OUT: hex value retrieved
* @param[in,out] hexLen IN: Buffersize; OUT: Actual amount of byte retrieved
* @param[in] minLen Minimum length in byte (values outside range cause a ::AX_CLI_ARG_RANGE_ERROR return value)
* @param[in] maxLen Maximum length in byte (values outside range cause a ::AX_CLI_ARG_RANGE_ERROR return value)
* @param[in] argc maximum amount of arguments passed as argument
* @param[in] argv argument array
* @param[in,out] argCurrent IN: Current argument; OUT: Next argument position (or end of array)
*
* @retval ::AX_CLI_EXEC_OK Upon successful execution
*/
int axCliGetHexString(char *szShortOption, char *szLongOption, U8 *hex, U16 *hexLen, int minLen, int maxLen, int argc, char ** argv, int *argCurrent)
{
    char szShort[64];

    // Do not go beyond the last argument when parsing
    if ((*argCurrent + 1) >= argc)
    {
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    // Long option not yet supported
    if (strcmp(szLongOption, "") != 0)
    {
        return AX_CLI_NOT_IMPLEMENTED;
    }

    szShort[0] = '-';
    strcpy(&szShort[1], szShortOption);

    if (strcmp(argv[*argCurrent], szShort) == 0) {
        // Check Hex String Argument size. The count of ASCII characters is double the byte count
        int nLen = (int)strlen(argv[*argCurrent+1]);
        if ( (nLen >= (minLen << 1)) && (nLen <= (maxLen << 1)) && ((nLen % 2) == 0 ) ) {
            int nRet = 0;
            nRet = axConvertHexString2ByteArray(hex, argv[*argCurrent+1], 0, (int)(nLen >> 1));
            *hexLen = (U16)(nLen >> 1);
            if (nRet == AX_UTIL_OK) {
#ifdef DBG_AX_CLI_UTIL
                axPrintByteArray("hex", hex, *hexLen, AX_COMPACT_32);
#endif
            }
            else {
                printf("axCliGetHexString: Cannot convert %s to HEX.\n", argv[*argCurrent+1]);
                return AX_CLI_ARG_VALUE_ERROR;
            }
        }
        else {
            printf("axCliGetHexString: argument has wrong length: %s\n\tlen=%d char\'s\n", 
				argv[*argCurrent+1], (int)nLen);
            printf("\tValid range: [%d:%d]\n", minLen << 1,  maxLen << 1);
            // DBGPRINTF("nLen = %d\n", nLen);
            // DBGPRINTF("minLen << 1 = %d\n", );
            // DBGPRINTF("maxLen << 1 = %d\n",);
            return AX_CLI_ARG_VALUE_ERROR;
        }
    }
    else {
        DBGPRINTF("Argument %s not expected\n", argv[*argCurrent]);
        return AX_CLI_ARG_OPTION_ERROR;
    }

    // Upon success.
    (*argCurrent) += 2;
    return AX_CLI_EXEC_OK;
}

/**
* Extract a string from argument array in case of matching option.
* Don't echo a warning to stdout when the option is missing
* \pre argCurrent points to correct position (argument option to be handled)
* \post argCurrent points to next argument option to be handled.
*
* \note szLongOption not yet supported
*
* @param[in] szShortOption  Name of option (excluding '-' character)
* @param[in] szLongOption  Pointer to the provided hash (or any other bytestring).
* @param[in,out] szString IN: Buffer to contain string; OUT: string retrieved
* @param[in,out] bufLen IN: Buffersize of szString
* @param[in] argc maximum amount of arguments passed as argument
* @param[in] argv argument array
* @param[in,out] argCurrent IN: Current argument; OUT: Next argument position (or end of array)
*
* @retval ::AX_CLI_EXEC_OK Upon successful execution
*/
int axCliGetOptionalString(char *szShortOption, char *szLongOption, char *szString, int bufLen, int argc, char ** argv, int *argCurrent)
{
    int mode = AX_CLI_GET_MODE_OPTIONAL;
    return axCliGetString_Internal(szShortOption, szLongOption, szString, bufLen, argc, argv, argCurrent, mode);
}

/**
* Extract a string from argument array in case of matching option
* \pre argCurrent points to correct position (argument option to be handled)
* \post argCurrent points to next argument option to be handled.
*
* \note szLongOption not yet supported
*
* @param[in] szShortOption  Name of option (excluding '-' character)
* @param[in] szLongOption  Pointer to the provided hash (or any other bytestring).
* @param[in,out] szString IN: Buffer to contain string; OUT: string retrieved
* @param[in,out] bufLen IN: Buffersize of szString
* @param[in] argc maximum amount of arguments passed as argument
* @param[in] argv argument array
* @param[in,out] argCurrent IN: Current argument; OUT: Next argument position (or end of array)
*
* @retval ::AX_CLI_EXEC_OK Upon successful execution
*/
int axCliGetString(char *szShortOption, char *szLongOption, char *szString, int bufLen, int argc, char ** argv, int *argCurrent)
{
    int mode = AX_CLI_GET_MODE_STRICT;
    return axCliGetString_Internal(szShortOption, szLongOption, szString, bufLen, argc, argv, argCurrent, mode);
}

static int axCliGetString_Internal(char *szShortOption, char *szLongOption, char *szString, int bufLen, int argc, char ** argv, int *argCurrent, int mode)
{
    char szShort[64];

    // Do not go beyond the last argument when parsing
    if ((*argCurrent + 1) >= argc)
    {
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    // Long option not yet supported
    if (strcmp(szLongOption, "") != 0)
    {
        return AX_CLI_NOT_IMPLEMENTED;
    }

    szShort[0] = '-';
    strcpy(&szShort[1], szShortOption);

    if (strcmp(argv[*argCurrent], szShort) == 0) {
        // Check Hex String Argument size. The count of ASCII characters is double the byte count
        int nLen = (int)strlen(argv[*argCurrent+1]);
        if ( nLen  < bufLen) {
            strcpy(szString, argv[*argCurrent+1]);
        }
        else {
            printf("axCliGetString: illegal argument (too long): %s\n", argv[*argCurrent+1]);
            return AX_CLI_ARG_VALUE_ERROR;
        }
    }
    else {
        if (mode != AX_CLI_GET_MODE_OPTIONAL) {
            printf("Argument %s not expected\n", argv[*argCurrent]);
        }
        return AX_CLI_ARG_OPTION_ERROR;
    }

    // Upon success.
    (*argCurrent) += 2;
    return AX_CLI_EXEC_OK;
}

/**
 * Convert a string into an ASCII key (of variable length) and a byte array of
 * fixed length. One needs to know the length of the expected byte array up front
 * Symbolic Representation of input string
 * <key> 00..FF
 *
 * @param[in,out] key        IN: buffer to contain key; OUT: key retrieved
 * @param[in]     keyBufSize Size of buffer key
 * @param[in,out] hex        IN: buffer to contain hex array of at least size hexLen; OUT: hex array retrieved
 * @param[in]     hexLen     IN: expected size of hex array
 * @param[in]     szLine     IN: line of text (string) that will be parsed
 */
int axCliGetKeyFixedLenHexValueFromLine(char *key, int keyBufSize, U8 *hex, U16 hexLen, const char *szLine)
{
    int nTokens = 0;
    char **myargv;
    int nRet = AX_CLI_EXEC_FAILED;
    int nLen = 0;

    if ((nRet = axMakeArgv(szLine, " \r\n", &myargv, &nTokens)) != AX_CLI_EXEC_OK) {
        DBGPRINTF("Could not make argument array for %s\n", szLine);
        return nRet;
    }

    if (nTokens == 2) {
        if ( (int)strlen(myargv[0]) < keyBufSize) {
            strcpy(key, myargv[0]);
            if ( (nLen = (int)strlen(myargv[1])) == (hexLen << 1)) {
                if ( axConvertHexString2ByteArray(hex, myargv[1], 0, hexLen) == AX_UTIL_OK ) {
                    nRet = AX_CLI_EXEC_OK;
                }
                else {
                    DBGPRINTF("ASCII-Hex-String %s cannot be converted to hex array.\n", myargv[1]);
                    nRet = AX_CLI_ARG_VALUE_ERROR;
                }
            }
            else {
                DBGPRINTF("ASCII-Hex-String %s wrong size.\n", myargv[1]);
                nRet = AX_CLI_ARG_VALUE_ERROR;
            }
        }
    }
    else {
        DBGPRINTF("Cannot handle input line: wrong number of tokens: %d\n", nTokens);
        DBGPRINTF("token[0]: %s\n", myargv[0]);
        DBGPRINTF("token[1]: %s\n", myargv[1]);
        nRet = AX_CLI_ARG_COUNT_MISTAKE;
    }
    axFreeArgv(myargv);
    return nRet;
}

int axMakeArgv(const char *s, const char *delimiters, char ***argvp, int *argc)
{
    int i;
    int nToken;
    const char *sStart;
    char *szCopy;

    *argc = 0;
    if ((s == NULL) || (delimiters == NULL) || (argvp == NULL))
    {
        return AX_CLI_ARG_VALUE_ERROR;
    }
    *argvp = NULL;
    sStart = s + strspn(s, delimiters);
    if ((szCopy = (char *)malloc(strlen(sStart) + 1)) == NULL)
    {
        return AX_CLI_DYN_ALLOC_ERROR;
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
        return AX_CLI_DYN_ALLOC_ERROR;
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
    return AX_CLI_EXEC_OK;
}

void axFreeArgv(char **argv)
{
   if (argv == NULL) { return; }
   if (*argv != NULL) { free(*argv); }
   free(argv);
}
