/*****************************************************************************
 *
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 ****************************************************************************/

#ifndef _AX_CRYPTOIPC_H
#define _AX_CRYPTOIPC_H

#define AX_CI_TRUE  1
#define AX_CI_FALSE 0

#ifdef __cplusplus
extern "C" {
#endif

int CryptoIpc_MutexInit(int setval);
void CryptoIpc_MutexLock(void);
void CryptoIpc_MutexUnlock(void);
char* CryptoIpc_ShmInit(void);
int CryptoIpc_Close(void);

#ifdef __cplusplus
}
#endif

#endif // _AX_CRYPTOIPC_H
