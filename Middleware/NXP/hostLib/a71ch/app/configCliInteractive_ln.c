/**
 * @file configCliInteractive.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command line handling 'interactive' entry (using linenoise command line editing support)
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
#include "linenoise.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#define FLOW_VERBOSE_PROBE_A70

#ifdef FLOW_VERBOSE_PROBE_A70
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

// #define DBG_A71CH_CONFIG_CLI_INTERACTIVE

#ifdef DBG_A71CH_CONFIG_CLI_INTERACTIVE
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

static int fInteractiveMode = AX_INTERACTIVE_MODE_OFF;

static const char *CmdHistoryFile = "a71chConfigCmdHistory.txt";

int a7xConfigCliGetInteractiveMode()
{
    return fInteractiveMode;
}

char *cliCmdInteractiveHints(const char *buf, int *color, int *bold) {
    if (!strcmp(buf, "apdu -cmd")) {
        *color = 35;
        *bold = 0;
        return " <hex> -sw <hex>";
    }
    if (!strcmp(buf, "erase cnt -x") || !strcmp(buf, "erase sym -x") ||
        !strcmp(buf, "erase pair -x") || !strcmp(buf, "erase pub -x") || !strcmp(buf, "ecrt -x")) {
        *color = 35;
        *bold = 0;
        return " <int>";
    }
    else if (!strcmp(buf, "gen pair -x")) {
        *color = 35;
        *bold = 0;
        return " <int>";
    }
    else if (!strcmp(buf, "info gp -h")) {
        *color = 35;
        *bold = 0;
        return " <hexvalue_offset:....> -n <segments>";
    }
    else if ((!strcmp(buf, "lock pair -x") || !strcmp(buf, "lock pub -x")) || !strcmp(buf, "lock sym -x")) {
        *color = 35;
        *bold = 0;
        return " <int>";
    }
    else if (!strcmp(buf, "lock gp -h")) {
        *color = 35;
        *bold = 0;
        return " <hexvalue_offset:....> -n <segments>";
    }
    else if (!strcmp(buf, "rcrt -x")) {
        *color = 35;
        *bold = 0;
        return " <int> [-c <certfile.crt>]";
    }
    else if (!strcmp(buf, "refpem -c")) {
        *color = 35;
        *bold = 0;
        return " <hexvalue:.. 10='key pair' 20='pub key'> -x <int> [-k <keyfile.pem>] -r <ref_keyfile.pem>";
    }
    else if (!strcmp(buf, "script -f")) {
        *color = 35;
        *bold = 0;
        return " <filename>";
    }
    else if (!strcmp(buf, "set gp -h")) {
        *color = 35;
        *bold = 0;
        return " <hexvalue_offset:....> -h <hexvalue_data>";
    }
    else if (!strcmp(buf, "transport unlock -h")) {
        *color = 35;
        *bold = 0;
        return " <hexvalue_tpkey>";
    }
    else if (!strcmp(buf, "ucrt -x")) {
        *color = 35;
        *bold = 0;
        return " <int> [-c <certfile.crt> | -h <hexvalue_data> | -p <certfile.pem>]";
    }
    else if (!strcmp(buf, "wcrt -x")) {
        *color = 35;
        *bold = 0;
        return " <int> [-c <certfile.crt> | -h <hexvalue_data> | -p <certfile.pem>]";
    }
    return NULL;
}

void cliCmdInteractiveCompletion(const char *buf, linenoiseCompletions *lc) {
    if (buf[0] == 'a') {
        linenoiseAddCompletion(lc, "apdu -cmd");
    }
    else if (buf[0] == 'c') {
        linenoiseAddCompletion(lc, "connect close");
        linenoiseAddCompletion(lc, "connect open");
    }
    else if (buf[0] == 'd') {
        linenoiseAddCompletion(lc, "debug reset");
    }
    else if (buf[0] == 'e') {
        if (buf[1] == 'r') {
            linenoiseAddCompletion(lc, "erase cnt -x");
            linenoiseAddCompletion(lc, "erase pair -x");
            linenoiseAddCompletion(lc, "erase pub -x");
            linenoiseAddCompletion(lc, "erase sym -x");
        }
        else if (buf[1] == 'c') {
            linenoiseAddCompletion(lc, "ecrt -x");
        }
        else {
            linenoiseAddCompletion(lc, "ecrt -x");
            linenoiseAddCompletion(lc, "erase cnt -x");
            linenoiseAddCompletion(lc, "erase pair -x");
            linenoiseAddCompletion(lc, "erase pub -x");
            linenoiseAddCompletion(lc, "erase sym -x");
        }
    }
    else if (buf[0] == 'g') {
        linenoiseAddCompletion(lc, "gen pair -x");
    }
    else if (buf[0] == 'h') {
        linenoiseAddCompletion(lc, "help");
    }
    else if (buf[0] == 'i') {
        linenoiseAddCompletion(lc, "info all");
        linenoiseAddCompletion(lc, "info cnt");
        linenoiseAddCompletion(lc, "info device");
        linenoiseAddCompletion(lc, "info gp -h");
        linenoiseAddCompletion(lc, "info objects");
        linenoiseAddCompletion(lc, "info pair");
        linenoiseAddCompletion(lc, "info pub");
        linenoiseAddCompletion(lc, "info status");
    }
    else if (buf[0] == 'l') {
        linenoiseAddCompletion(lc, "lock pair -x");
        linenoiseAddCompletion(lc, "lock pub -x");
        linenoiseAddCompletion(lc, "lock sym -x");
        linenoiseAddCompletion(lc, "lock gp -h");
        linenoiseAddCompletion(lc, "lock inject_plain");
    }
    else if (buf[0] == 'o') {
        linenoiseAddCompletion(lc, "obj erase -x");
        linenoiseAddCompletion(lc, "obj get -x");
        linenoiseAddCompletion(lc, "obj update -x");
        linenoiseAddCompletion(lc, "obj write -x");
    }
    else if (buf[0] == 'r') {
        if (buf[1] == 'c') {
            linenoiseAddCompletion(lc, "rcrt -x");
        }
        else if (buf[1] == 'e') {
            linenoiseAddCompletion(lc, "refpem -c");
        }
        else {
            linenoiseAddCompletion(lc, "rcrt -x");
            linenoiseAddCompletion(lc, "refpem -c");
        }
    }
    else if (buf[0] == 's') {
        if (buf[1] == 'c') {
            linenoiseAddCompletion(lc, "scp auth -h");
            linenoiseAddCompletion(lc, "scp put -h");
            linenoiseAddCompletion(lc, "script -f");
        }
        else if (buf[1] == 'e') {
            linenoiseAddCompletion(lc, "set cnt -x");
            linenoiseAddCompletion(lc, "set gp -h");
            linenoiseAddCompletion(lc, "set pair -x");
            linenoiseAddCompletion(lc, "set pub -x");
            linenoiseAddCompletion(lc, "set sym -x");
        }
        else {
            linenoiseAddCompletion(lc, "scp auth -h");
            linenoiseAddCompletion(lc, "scp put -h");
            linenoiseAddCompletion(lc, "script -f");
            linenoiseAddCompletion(lc, "set cnt -x");
            linenoiseAddCompletion(lc, "set gp -h");
            linenoiseAddCompletion(lc, "set pair -x");
            linenoiseAddCompletion(lc, "set pub -x");
            linenoiseAddCompletion(lc, "set sym -x");
        }
    }
    else if (buf[0] == 't') {
        linenoiseAddCompletion(lc, "transport lock");
        linenoiseAddCompletion(lc, "transport unlock -h");
    }
    else if (buf[0] == 'u') {
        linenoiseAddCompletion(lc, "ucrt -x");
    }
    else if (buf[0] == 'w') {
        linenoiseAddCompletion(lc, "wcrt -x");
    }
}

int a7xConfigCliCmdInteractive(int argc, char ** argv)
{
    int nRet = AX_CLI_EXEC_FAILED;
    char **myargv;
    int nTokens = 0;
    char *szLine = NULL;
#ifdef DBG_A71CH_CONFIG_CLI_INTERACTIVE
    int i = 0;
#endif

    fInteractiveMode = AX_INTERACTIVE_MODE_ON;
    // cliCmdInteractiveCompletion will be called everytime the <tab> key is hit
    linenoiseSetCompletionCallback(cliCmdInteractiveCompletion);
    linenoiseSetHintsCallback(cliCmdInteractiveHints);
    linenoiseHistoryLoad(CmdHistoryFile);

    while ((szLine = linenoise(">>> ")) != NULL)
    {
        if (strncmp(szLine, "quit", 4) == 0) {
            nRet = AX_CLI_EXEC_OK;
            free(szLine);
            break;
        }
        linenoiseHistoryAdd(szLine);
        nTokens = 0;
        if ((nRet = axMakeArgv(szLine, " \n", &myargv, &nTokens)) != AX_CLI_EXEC_OK) {
            fprintf(stderr, "Could not make argument array for %s\n", szLine);
            free(szLine);
            continue;
        }
#ifdef DBG_A71CH_CONFIG_CLI_INTERACTIVE
        printf("The argument array contains (%d tokens):\n", nTokens);
        for (i = 0; i < nTokens; i++) {
            printf("[%d]:%s\n", i, myargv[i]);
        }
#endif
        nRet = a7xConfigCli("interactive", nTokens, myargv);
        axFreeArgv(myargv);
        free(szLine);
    }

    linenoiseHistorySave(CmdHistoryFile);
    fInteractiveMode = AX_INTERACTIVE_MODE_OFF;
    return nRet;
}
