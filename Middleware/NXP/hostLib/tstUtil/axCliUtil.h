/**
 * @file axCliUtil.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Public interface of command line utility functions
 */
#ifndef _AX_CLI_UTIL_H_
#define _AX_CLI_UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// project specific include files
#include "sm_types.h"
// #include "sm_apdu.h"

// #include "axHostCrypto.h"
// #include "tstHostCrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AX_CLI_EXEC_OK                0
#define AX_CLI_EXEC_FAILED            1
#define AX_CLI_ERR_IP_ADR_MISSING    10
#define AX_CLI_ERR_CANNOT_CONNECT    11
#define AX_CLI_ERR_SELECT_FAILS      12

#define AX_CLI_NOT_IMPLEMENTED       20
#define AX_CLI_CHECK_USAGE           21
#define AX_CLI_PEM_CONVERT_FAILED    22
#define AX_CLI_FILE_OPEN_FAILED      23
#define AX_CLI_FILE_PEM_READ_FAILED  24
#define AX_CLI_FILE_PEM_WRITE_FAILED 25
#define AX_CLI_BIT_CURVE_ERROR       26
#define AX_CLI_DYN_ALLOC_ERROR       27
#define AX_CLI_EXEC_HALTED           28
#define AX_CLI_FILE_FORMAT_ERROR     29

#define AX_CLI_ARG_RANGE_ERROR       30 //!< axCli utilities can check whether an argument falls in a specified range (e.g. 349 is outside [0:256] interval)
#define AX_CLI_ARG_NAME_ERROR        31 //!< Not used; Candidate for removal
#define AX_CLI_ARG_OPTION_ERROR      32 //!< Passed wrong option on command line (e.g. -x instead of -i)
#define AX_CLI_ARG_COUNT_MISTAKE     33 //!< Insufficient/Too much arguments were passed
#define AX_CLI_ARG_VALUE_ERROR       34 //!< Argument not supported
#define AX_CLI_BUFFER_SIZE_ERROR     35
#define AX_CLI_WRAP_ERROR            36 //!< Key wrap failed
#define AX_CLI_NO_OBJECTS            37 //!< Enumerating objects has not found any object
#define AX_CLI_OBJECT_NOT_FOUND      38 //!< Enumerating objects has not found the specific object
#define AX_CLI_WRITE_CER_FILE_ERROR  39 //!< Write certificate failed
#define AX_CLI_ERASE_CER_FILE_ERROR  40 //!< Erase certificate failed
#define AX_CLI_UPDATE_CER_FILE_ERROR 41 //!< Update certificate failed

#define AX_CLI_API_ERROR             42

char *axGetErrorString(int errorCode);
int axCliGetInteger(char *szShortOption, char *szLongOption, int *value, int minVal, int maxVal, int argc, char ** argv, int *argCurrent);
int axCliGetHexString(char *szShortOption, char *szLongOption, U8 *hex, U16 *hexLen, int minLen, int maxLen, int argc, char ** argv, int *argCurrent);
int axCliGetString(char *szShortOption, char *szLongOption, char *szString, int bufLen, int argc, char ** argv, int *argCurrent);
int axCliGetOptionalString(char *szShortOption, char *szLongOption, char *szString, int bufLen, int argc, char ** argv, int *argCurrent);
int axMakeArgv(const char *s, const char *delimiters, char ***argvp, int *argc);
void axFreeArgv(char **argv);

int axCliGetKeyFixedLenHexValueFromLine(char *key, int keyLen, U8 *hex, U16 hexLen, const char *szLine);

#ifdef __cplusplus
}
#endif
#endif // _AX_CLI_UTIL_H_
