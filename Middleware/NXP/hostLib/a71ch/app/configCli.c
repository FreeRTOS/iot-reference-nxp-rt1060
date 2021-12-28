/**
 * @file
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling main entry
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

/**
 * @brief      Usage of the A71CH Config Tool
 *
 * Simply invoking the tool in standalone mode on an MCIMX6UL-EVKB board results in the following
 * output (some output edited away)
 *
 *     root@imx6ulevk:~# ./a71chConfig_i2c_imx
 *     a71chConfig (Rev 1.00) .. connect to A71CH. Chunksize at link layer = 256.
 *     ...
 *     Applet-Rev:SecureBox-Rev   : 0x0131:0x0000
 *     ****************************
 *     Usage: a71chConfig [apdu|debug|erase|gen|info|interactive|lock|rcrt|scp|set|wcrt|help] <OptArg>
 *         apdu -cmd <hexval> -sw <hexval>
 *         debug [permanently_disable_debug|reset]
 *         ecrt -x <int>
 *         erase [cnt|pair|pub|sym] -x <int>
 *         gen pair -x <int>
 *         get pub -c <hex_value> -x <int> -k <keyfile.pem>
 *         info [all|cnt|device|objects|pair|pub|status]
 *         info gp -h <hexvalue_offset> -n <segments>
 *         interactive
 *         lock [pair|pub] -x <int>
 *         lock gp -h <hexvalue_offset> -n <segments>
 *         lock inject_plain
 *         obj erase -x <int>
 *         obj get -x <int> [-h <hexvalue_offset>] [-s <hexvalue_size>] [-f <data.txt> -t [hex_16|hex_32]]
 *         obj update -x <int> -h <hexvalue_offset> [-f <data.txt> -t [hex_16|hex_32] | -h <hexvalue_data>]
 *         obj write -x <int> [-f <data.txt> -t [hex_16|hex_32] | -h <hexvalue_data> | -n <segments>]
 *         rcrt -x <int> [-c <certfile.crt>]
 *         refpem -c <hex_value> -x <int> [-k <keyfile.pem>] -r <ref_keyfile.pem>
 *         script -f <script.txt>
 *         scp [put|auth] -h <hexvalue_keyversion> -k <keyfile>
 *         set gp -h <hexvalue_offset> -h <hexvalue_data>
 *         set pair -x <int> [-k <keyfile.pem> | -h <hexvalue_pub> -h <hexvalue_priv>] [-w <hexvalue_wrap_key>]
 *         set pub  -x <int> [-k <keyfile.pem> | -h <hexvalue>] [-w <hexvalue_wrap_key>]
 *         set [cfg|cnt|sym]  -x <int> -h <hexvalue> [-w <hexvalue_wrap_key>]
 *         transport [lock|unlock -h <hexvalue_tpkey>]
 *         ucrt -x <int> [-c <certfile.crt> | -h <hexvalue_data> | -p <certfile.pem>]
 *         wcrt -x <int> [-c <certfile.crt> | -h <hexvalue_data> | -p <certfile.pem>] [-n <padding-segments>]
 *     ****************************
 */
int a7xConfigCliHelp(char *szName)
{
    if ( strcmp(szName, "interactive") == 0)
    {
        printf("[apdu|debug|erase|gen|info|lock|scp|set|help|quit] <OptArg>\n");
    }
    else
    {
        printf("****************************\n");
        printf("Usage: %s ", szName);
#if defined(SMCOM_JRCP_V1)
        printf("[ip-address:8050] ");
#endif
        printf("[apdu|debug|erase|gen|info|interactive|lock|scp|set|help|...] <OptArg>\n");
    }
    printf("    apdu -cmd <hexvalue> -sw <hexvalue>\n");
    if ( strcmp(szName, "interactive") == 0)
    {
        printf("    connect [close|open]\n");
    }
    printf("    debug [permanently_disable_debug|reset]\n");
    printf("    ecrt -x <int>\n");
    printf("    erase [cnt|pair|pub|sym] -x <int>\n");
    printf("    gen pair -x <int>\n");
    printf("    get pub -c <hex_value> -x <int> -k <keyfile.pem>\n");
    printf("    info [all|cnt|device|objects|pair|pub|status]\n");
    printf("    info gp -h <hexvalue_offset> -n <segments>\n");
    if ( strcmp(szName, "interactive") != 0)
    {
        printf("    interactive\n");
    }
    printf("    lock [pair|pub] -x <int>\n");
    printf("    lock gp -h <hexvalue_offset> -n <segments>\n");
    printf("    lock inject_plain\n");
    printf("    obj erase -x <int>\n");
    printf("    obj get -x <int> [-h <hexvalue_offset>] [-s <hexvalue_size>]  [-f <data.txt> -t [hex_16|hex_32]]\n");
    printf("    obj update -x <int> -h <hexvalue_offset> [-f <data.txt> -t [hex_16|hex_32] | -h <hexvalue_data>]\n");
    printf("    obj write -x <int> [-f <data.txt> -t [hex_16|hex_32] | -h <hexvalue_data> | -n <segments>]\n");
    printf("    rcrt -x <int> [-c <certfile.crt>]\n");
    printf("    refpem -c <hex_value> -x <int> [-k <keyfile.pem>] -r <ref_keyfile.pem>\n");
    printf("    script -f <script.txt>\n");
    printf("    scp [put|auth] -h <hexvalue_keyversion> -k <keyfile>\n");
    if ( strcmp(szName, "interactive") == 0)
    {
        printf("    scp clear_host\n");
    }
    printf("    set gp -h <hexvalue_offset> -h <hexvalue_data>\n");
    printf("    set gp -h <hexvalue_offset> -c <certfile.pem>\n"); // deprecated
    printf("    set pair -x <int> [-k <keyfile.pem> | -h <hexvalue_pub> -h <hexvalue_priv>] [-w <hexvalue_wrap_key>]\n");
    printf("    set pub  -x <int> [-k <keyfile.pem> | -h <hexvalue>] [-w <hexvalue_wrap_key>]\n");
    printf("    set [cfg|cnt|sym]  -x <int> -h <hexvalue> [-w <hexvalue_wrap_key>]\n");
    printf("    transport [lock|unlock -h <hexvalue_tpkey>]\n");
    printf("    ucrt -x <int> [-c <certfile.crt> | -h <hexvalue_data> | -p <certfile.pem>]\n");
    printf("    wcrt -x <int> [-c <certfile.crt> | -h <hexvalue_data> | -p <certfile.pem>] [-n <padding-segments>]\n");
    if ( strcmp(szName, "interactive") != 0)
    {
        printf("****************************\n");
    }
    return AX_CLI_CHECK_USAGE;
}

// Parses commandline and invokes proper command
// \note Before this is called the optional IP:PORT argument has been stripped.
// \returns Returns ::AX_CLI_EXEC_OK upon success
int a7xConfigCli(char *progname, int argc, char **argv)
{
    int nRet = AX_CLI_EXEC_OK;
#ifdef DBG_PROBE_A70
    int i = 0;
#endif
    U16 sw = 0;

    DBGPRINTF("a7xConfigCli (%s): %d arguments left to parse.\n", progname, argc);
#ifdef DBG_PROBE_A70
    for (i=0; i<argc; i++) {
        DBGPRINTF("\t Arg=%d: %s\n", i, argv[i]);
    }
#endif

    if (argc < 1)
    {
        a7xConfigCliHelp(progname);
        return AX_CLI_ARG_COUNT_MISTAKE;
    }

    if (strncmp(argv[0], "info", sizeof("info")) == 0)
    {
        nRet = a7xConfigCliCmdInfo(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "apdu", sizeof("apdu")) == 0) {
        nRet = a7xConfigCliCmdApdu(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "connect", sizeof("connect")) == 0) {
        nRet = a7xConfigCliCmdConnect(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "debug", sizeof("debug")) == 0) {
        nRet = a7xConfigCliCmdDebug(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "erase", sizeof("erase")) == 0) {
        nRet = a7xConfigCliCmdErase(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "gen", sizeof("gen")) == 0) {
        nRet = a7xConfigCliCmdGen(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "wcrt", sizeof("wcrt")) == 0 || strncmp(argv[0], "ucrt", sizeof("ucrt")) == 0) {
        nRet = a7xConfigCliCmdWcrt(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "rcrt", sizeof("rcrt")) == 0) {
        nRet = a7xConfigCliCmdRcrt(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "ecrt", sizeof("ecrt")) == 0) {
        nRet = a7xConfigCliCmdEcrt(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "get", sizeof("get")) == 0) {
        nRet = a7xConfigCliCmdGet(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "obj", sizeof("obj")) == 0) {
        nRet = a7xConfigCliCmdObj(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "help", sizeof("help")) == 0) {
        a7xConfigCliHelp(progname);
        nRet = AX_CLI_EXEC_OK;
    }
    else if (strncmp(argv[0], "interactive", sizeof("interactive")) == 0) {
        if (a7xConfigCliGetInteractiveMode() == AX_INTERACTIVE_MODE_OFF) {
            nRet = a7xConfigCliCmdInteractive(argc, argv);
        }
        else {
            printf("Interactive mode already on.\n");
        }
    }
    else if (strncmp(argv[0], "lock", sizeof("lock")) == 0) {
        nRet = a7xConfigCliCmdLock(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "refpem", sizeof("refpem")) == 0) {
        nRet = a7xConfigCliCmdRefpem(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "scp", sizeof("scp")) == 0) {
        nRet = a7xConfigCliCmdScp(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "script", sizeof("script")) == 0) {
        nRet = a7xConfigCliCmdScript(argc, argv);
    }
    else if (strncmp(argv[0], "set", sizeof("set")) == 0) {
        nRet = a7xConfigCliCmdSet(argc, argv, &sw);
    }
    else if (strncmp(argv[0], "transport", sizeof("transport")) == 0) {
        nRet = a7xConfigCliCmdTransport(argc, argv, &sw);
    }
    else {
        printf("'%s' is an unknown command\n", argv[0]);
        nRet = a7xConfigCliHelp(progname);
    }

    if (nRet != AX_CLI_EXEC_OK) {
        printf("Command Failed (%s (%d)", axGetErrorString(nRet), nRet);
        if (nRet == AX_CLI_EXEC_FAILED) {
            printf(": sw=0x%04X)\n", sw);
        }
        else {
            printf(")\n");
        }
    }

    return nRet;
}
