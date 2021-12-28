/**
 * @file accessManager_com.h
 * @author NXP Semiconductors
 * @version 1.0
 * @section LICENSE
 * ----------------------------------------------------------------------------
 *
 * Copyright 2016, 2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------------
 * @section DESCRIPTION
 * This file defines the API of the RemoteJCTerminal implementation.
 * ----------------------------------------------------------------------------
 * @section HISTORY
 * 1.0   06-may-2014 : Initial version
 *
 *****************************************************************************/
#ifndef _ACCESS_MANAGER_COM_H_
#define _ACCESS_MANAGER_COM_H_

#include "sm_types.h"

typedef struct {
    U16 param1;
    U16 param2;
    U32 appletVersion;
    U16 sbVersion;
} SmCommStateAm_t;

U16 SM_ConnectAm(SmCommStateAm_t *commState, U8 *atr, U16 *atrLen);
U16 SM_SendAPDUAm(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen, U8 platformSCP03_On);
U16 SM_CloseAm(U8 mode);

U16 SM_EstablishPlatformSCP03Am(SmCommStateAm_t *commState);

#if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)
U16 SM_EstablishA71CHPlatformSCP03Am();
#endif


#if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)

#define A71CH_SCP03_PATH_ENV "A71CH_SCP03_PATH_ENV"

#define SCP03_A71CH_KEY_ENC                                                            				   \
    {                                                                                                  \
        0xEE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF \
    }

#define SCP03_A71CH_KEY_MAC                                                                            \
    {                                                                                                  \
        0xAA, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF \
    }

#define SCP03_A71CH_KEY_DEK                                                                            \
    {                                                                                                  \
        0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF \
    }

#endif //#if (SSS_HAVE_A71CH || SSS_HAVE_A71CH_SIM)

#endif // _ACCESS_MANAGER_COM_H_
