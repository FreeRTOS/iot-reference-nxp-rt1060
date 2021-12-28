/**
 * @file probeAxUtil.h
 * @author NXP Semiconductors
 * @version 1.0
 * @section LICENSE
 * ----------------------------------------------------------------------------
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------------
 * @section DESCRIPTION
 * API of probe utility functions specific to JCOP2.4.2
 * ----------------------------------------------------------------------------
 * @section HISTORY
 * 1.0   11-may-2016 : Initial version
 *
 *****************************************************************************/
#ifndef _PROBE_AX_UTIL_H_
#define _PROBE_AX_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "sm_types.h"
#include "sm_printf.h"
#include "ax_api.h"

// This module implements generic probe functions
U16 probeAxIdentifyFetchPrint();
U16 probeAxSelectCardmanager();
U16 probeAxGetCplcDataFetchPrint();

#ifdef __cplusplus
}
#endif
#endif // _PROBE_AX_UTIL_H_
