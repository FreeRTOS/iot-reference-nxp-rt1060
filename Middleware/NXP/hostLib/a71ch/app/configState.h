/**
 * @file configState.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Configuration tool internal state handling functions
 */
#ifndef _CONFIG_STATE_H_
#define _CONFIG_STATE_H_


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
#include "a71ch_api.h"
#include "axCliUtil.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AX_SCP03_CHANNEL_OFF      0x00
#define AX_SCP03_CHANNEL_ON       0x01
#define AX_SCP03_CHANNEL_ILLEGAL  0x0F

int a7xConfigSetHostScp03State(U8 state);
U8 a7xConfigGetHostScp03State();

int a7xConfigSetConnectString(const char *szString);
const char *a7xConfigGetConnectString();

#ifdef __cplusplus
}
#endif
#endif // _CONFIG_STATE_H_
