/*****************************************************************************
 *
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#ifndef _AX_CRYPTOIPC_H
#define _AX_CRYPTOIPC_H

#define AX_CI_TRUE 1
#define AX_CI_FALSE 0

#ifdef __cplusplus
extern "C" {
#endif

int axCi_MutexInit(int setval);
void axCi_MutexLock(void);
void axCi_MutexUnlock(void);
int axCi_Close(void);

#ifdef __cplusplus
}
#endif

#endif // _AX_CRYPTOIPC_H
