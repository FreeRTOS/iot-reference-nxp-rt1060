/**
 * @file configCli.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling functions
 */
#ifndef _CONFIG_CLI_H_
#define _CONFIG_CLI_H_

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
#include "axCliUtil.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AX_INTERACTIVE_MODE_OFF 0
#define AX_INTERACTIVE_MODE_ON  1

#define AX_LINE_MAX 1024
#define AX_FILENAME_MAX 256

int a7xConfigCliHelp(char *szName);
int a7xConfigCli(char *progname, int argc, char **argv);
int a7xConfigCliGetInteractiveMode();

int a7xConfigCliCmdApdu(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdConnect(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdDebug(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdErase(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdGen(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdInfo(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdInteractive(int argc, char **argv);
int a7xConfigCliCmdLock(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdRefpem(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdScp(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdScript(int argc, char **argv);
int a7xConfigCliCmdSet(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdTransport(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdWcrt(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdRcrt(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdEcrt(int argc, char **argv, U16 *sw);
int a7xConfigCliCmdObj(int argc, char ** argv, U16 *sw);
int a7xConfigCliCmdGet(int argc, char ** argv, U16 *sw);

#ifdef __cplusplus
}
#endif
#endif // _CONFIG_CLI_H_
