/*
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// project specific include files
#include "sm_types.h"
#include "sm_apdu.h"
#include "tst_sm_util.h"
#include "global_platf.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#include "probeAxUtil.h"

// #define FLOW_VERBOSE_PROBE_A70

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

#define JCOP_242R1_IDENTIFY_RSP_LEN   21
#define JCOP_242R2_IDENTIFY_RSP_LEN   22

#define IDY_FABKEY_ID_OFFSET      0
#define IDY_PATCH_ID_OFFSET       1
#define IDY_TARGET_ID_OFFSET      2
#define IDY_MASK_ID_OFFSET        3
#define IDY_CUSTOM_MASK_ID_OFFSET 4
#define IDY_MASK_NAME_OFFSET      8
#define IDY_FUSED_STATE_OFFSET   14
#define IDY_ROM_INFO_LEN_OFFSET  15
#define IDY_ROM_INFO_OFFSET      16
#define IDY_FIPS_OFFSET          19

#define JCOP_242_GETCPLC_DATA_RSP_LEN 47
#define GET_CPLC_DATA_OFFSET           3
#define CPLC_IC_MOD_FAB_OFFSET         (GET_CPLC_DATA_OFFSET + 0x12)
#define CPCL_IC_MOD_PACK_DATE_OFFSET   (GET_CPLC_DATA_OFFSET + 0x14)
#define CPCL_ICC_MANUFACT_OFFSET       (GET_CPLC_DATA_OFFSET + 0x16)
#define CPCL_IC_EMBED_DATE_OFFSET      (GET_CPLC_DATA_OFFSET + 0x18)
#define CPCL_IC_PRE_PERSO_OFFSET       (GET_CPLC_DATA_OFFSET + 0x1A)

// TODO: Split fetching of value and printing out of value in two functions
U16 probeAxIdentifyFetchPrint()
{
    U16 sw;
    U8 resp[128];
    U16 respLen = sizeof(resp);
    U8 cmdIdentify[] = { 0x00, INS_GP_SELECT, 0x04, 0x00, 0x09,
                         0xA0, 0x00, 0x00, 0x01, 0x67, 0x41, 0x30, 0x00, 0xFF,
                         0x00 };
    DBGPRINTF("DBG: probeAxIdentifyFetchPrint().\n");
    respLen = sizeof(resp);
    sw = SM_SendAPDU(cmdIdentify, (U16) sizeof(cmdIdentify), resp, &respLen);
    // DBGPRINTF("DBG: respLen: %d.\n", respLen);
    if ( (respLen == JCOP_242R1_IDENTIFY_RSP_LEN) || (respLen == JCOP_242R2_IDENTIFY_RSP_LEN) )
    {
        if ( ((U16)(resp[respLen-2]<<8) + resp[respLen-1]) == SW_FILE_NOT_FOUND  )
        {
            printf("Fabkey ID      : 0x%02X\n", resp[IDY_FABKEY_ID_OFFSET]);
            printf("Patch ID       : 0x%02X\n", resp[IDY_PATCH_ID_OFFSET]);
            printf("Target ID      : 0x%02X\n", resp[IDY_TARGET_ID_OFFSET]);
            printf("Mask ID        : 0x%02X (%d)\n", resp[IDY_MASK_ID_OFFSET], (resp[IDY_MASK_ID_OFFSET] & 0x00FF) );
            printf("Custom Mask ID : 0x%02X:%02X:%02X:%02X\n", resp[IDY_CUSTOM_MASK_ID_OFFSET], resp[IDY_CUSTOM_MASK_ID_OFFSET+1],
                resp[IDY_CUSTOM_MASK_ID_OFFSET+2], resp[IDY_CUSTOM_MASK_ID_OFFSET+3]);
            printf("Mask Name      : %c%c%c%c%c%c\n", resp[IDY_MASK_NAME_OFFSET], resp[IDY_MASK_NAME_OFFSET+1], resp[IDY_MASK_NAME_OFFSET+2],
                resp[IDY_MASK_NAME_OFFSET+3], resp[IDY_MASK_NAME_OFFSET+4], resp[IDY_MASK_NAME_OFFSET+5]);
            printf("Fused State    : 0x%02X\n", resp[IDY_FUSED_STATE_OFFSET]);
            printf("Rom Info Len   : %d\n", resp[IDY_ROM_INFO_LEN_OFFSET]);
            printf("Rom Info       : 0x%02X:%02X:%02X\n", resp[IDY_ROM_INFO_OFFSET], resp[IDY_ROM_INFO_OFFSET+1], resp[IDY_ROM_INFO_OFFSET+2]);
            if (respLen == JCOP_242R2_IDENTIFY_RSP_LEN)
            {
                printf("FIPS           : 0x%02X\n", resp[IDY_FIPS_OFFSET]);
            }
        }
        else
        {
            printf("Identify command failed.\n");
            axPrintByteArray("Command Response", resp, respLen, AX_COLON_32);
        }
    }
    else
    {
        printf("Identify command failed.\n");
        axPrintByteArray("Command Response", resp, respLen, AX_COLON_32);
    }

    return sw;
}

// TODO: Split fetching of value and printing out of value in two functions
U16 probeAxSelectCardmanager()
{
    U16 sw_raw;
    U16 sw_response;
    U8 resp[200];
    U16 respLen = sizeof(resp);
    U8 cmdIdentify[] = { 0x00, INS_GP_SELECT, 0x04, 0x00, 0x00 };
    DBGPRINTF("DBG: probeAxSelectCardmanager().\n");
    respLen = sizeof(resp);
    sw_raw = SM_SendAPDU(cmdIdentify, (U16) sizeof(cmdIdentify), resp, &respLen);
    if (sw_raw == SW_OK)
    {
        sw_response = (U16)((resp[respLen-2]<<8) + resp[respLen-1]);
        if ( sw_response == SW_OK  )
        {
            printf("Select Card Manager command OK.\n");
            // axPrintByteArray("Command Response", resp, respLen, AX_COLON_32);
        }
        else
        {
            printf("Select Card Manager command FAILED.\n");
            axPrintByteArray("Command Response", resp, respLen, AX_COLON_32);
            sw_raw = sw_response;
        }
    }

    return sw_raw;
}

// TODO: Split fetching of value and printing out of value in two functions
U16 probeAxGetCplcDataFetchPrint()
{
    U16 sw;
    U8 resp[128];
    U16 respLen = sizeof(resp);
    U8 cmdIdentify[] = { 0x80, 0xCA, 0x9F, 0x7F, 0x00 };
    DBGPRINTF("DBG: probeAxGetCplcDataFetchPrint().\n");
    respLen = sizeof(resp);
    sw = SM_SendAPDU(cmdIdentify, (U16) sizeof(cmdIdentify), resp, &respLen);
    // DBGPRINTF("DBG: respLen: %d.\n", respLen);
    if ( respLen == JCOP_242_GETCPLC_DATA_RSP_LEN )
    {
        if ( ((U16)(resp[respLen-2]<<8) + resp[respLen-1]) == SW_OK  )
        {
            printf("CPLC Data:\n");
            printf("IC Fabricator  : 0x%02X:%02X\n", resp[GET_CPLC_DATA_OFFSET], resp[GET_CPLC_DATA_OFFSET+1]);
            printf("IC Type        : 0x%02X:%02X\n", resp[GET_CPLC_DATA_OFFSET+2], resp[GET_CPLC_DATA_OFFSET+3]);
            printf("OS ID          : 0x%02X:%02X\n", resp[GET_CPLC_DATA_OFFSET+4], resp[GET_CPLC_DATA_OFFSET+5]);
            printf("OS Rel Date    : 0x%02X:%02X\n", resp[GET_CPLC_DATA_OFFSET+6], resp[GET_CPLC_DATA_OFFSET+7]);
            printf("OS Rel Level   : 0x%02X:%02X\n", resp[GET_CPLC_DATA_OFFSET+8], resp[GET_CPLC_DATA_OFFSET+9]);
            printf("IC Fab Date    : 0x%02X:%02X\n", resp[GET_CPLC_DATA_OFFSET+10], resp[GET_CPLC_DATA_OFFSET+11]);
            printf("IC Ser Nr      : 0x%02X:%02X:%02X:%02X\n",
                resp[GET_CPLC_DATA_OFFSET+12], resp[GET_CPLC_DATA_OFFSET+13],resp[GET_CPLC_DATA_OFFSET+14], resp[GET_CPLC_DATA_OFFSET+15]);
            printf("IC Batch ID    : 0x%02X:%02X\n", resp[GET_CPLC_DATA_OFFSET+16], resp[GET_CPLC_DATA_OFFSET+17]);
            printf("IC Mod Fab     : 0x%02X:%02X\n", resp[CPLC_IC_MOD_FAB_OFFSET], resp[CPLC_IC_MOD_FAB_OFFSET+1]);
            printf("IC Mod PackDate: 0x%02X:%02X\n", resp[CPCL_IC_MOD_PACK_DATE_OFFSET], resp[CPCL_IC_MOD_PACK_DATE_OFFSET+1]);
            printf("ICC Manufact   : 0x%02X:%02X\n", resp[CPCL_ICC_MANUFACT_OFFSET], resp[CPCL_ICC_MANUFACT_OFFSET+1]);
            printf("IC Embed Date  : 0x%02X:%02X\n", resp[CPCL_IC_EMBED_DATE_OFFSET], resp[CPCL_IC_EMBED_DATE_OFFSET+1]);
            printf("IC Pre-Perso   : 0x%02X:%02X\n", resp[CPCL_IC_PRE_PERSO_OFFSET], resp[CPCL_IC_PRE_PERSO_OFFSET+1]);
            printf("NOTE: Remaining CPLC data not printed out...\n");
        }
        else
        {
            printf("GetCplcData command failed.\n");
            axPrintByteArray("Command Response", resp, respLen, AX_COLON_32);
        }
    }
    else
    {
        printf("GetCplcData command failed.\n");
        axPrintByteArray("Command Response", resp, respLen, AX_COLON_32);
    }

    return sw;
}
