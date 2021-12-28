/**
 * @file configCmd.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Configuration handling functions
 */
#ifndef _CONFIG_CMD_H_
#define _CONFIG_CMD_H_

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

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_FILE_PATH 1024
#define MAX_OBJECTS_NUM 256

#define A7X_CONFIG_STATUS_API_ERROR 0x8050

// ENSURE THESE MAX VALUES ARE CORRECT
#define A7X_CONFIG_KEY_PAIR_MAX      4 //!< Maximum amount of ECC key pairs that can be stored in A71CH
#define A7X_CONFIG_PUBLIC_KEY_MAX    4 //!< Maximum amount of ECC public keys that can be stored in A71CH
#define A7X_CONFIG_CFG_KEY_MAX       3 //!< Maximum amount of 128 bit configuration keys that can be stored in A71CH
#define A7X_CONFIG_SYM_KEY_MAX       8 //!< Maximum amount of 128 bit symmetric keys that can be stored in A71CH
#define A7X_CONFIG_COUNTER_MAX       2 //!< Maximum amount of monotonic counters that can be stored in A71CH
#define A7X_CONFIG_GP_STORAGE_SECTION_MAX (A71CH_GP_STORAGE_SIZE_B / A71CH_GP_STORAGE_GRANULARITY)
#define A7X_CONFIG_GP_STORAGE_MAX    A71CH_GP_STORAGE_SIZE_B

// TYPE A Device
#define A7X_CONFIG_MAP_SIZE_A71CH_TYPE_A  (1+\
    A7X_CONFIG_KEY_PAIR_TYPE_A +\
    A7X_CONFIG_PUBLIC_KEY_TYPE_A +\
    A7X_CONFIG_CFG_KEY_TYPE_A +\
    A7X_CONFIG_SYM_KEY_TYPE_A +\
    A7X_CONFIG_COUNTER_TYPE_A +\
    A7X_CONFIG_GP_STORAGE_SECTION_TYPE_A)
#define A7X_CONFIG_KEY_PAIR_TYPE_A      2 //!< Actual amount of ECC key pairs that can be stored in A71CH
#define A7X_CONFIG_PUBLIC_KEY_TYPE_A    2 //!< Actual amount of ECC public keys that can be stored in A71CH
#define A7X_CONFIG_CFG_KEY_TYPE_A       3 //!< Actual amount of 128 bit configuration keys that can be stored in A71CH
#define A7X_CONFIG_SYM_KEY_TYPE_A       4 //!< Actual amount of 128 bit symmetric keys that can be stored in A71CH
#define A7X_CONFIG_COUNTER_TYPE_A       2 //!< Actual amount of monotonic counters that can be stored in A71CH
#define A7X_CONFIG_GP_STORAGE_SECTION_TYPE_A 32

// TYPE B Device
#define A7X_CONFIG_MAP_SIZE_A71CH_TYPE_B  (1+\
    A7X_CONFIG_KEY_PAIR_TYPE_B +\
    A7X_CONFIG_PUBLIC_KEY_TYPE_B +\
    A7X_CONFIG_CFG_KEY_TYPE_B +\
    A7X_CONFIG_SYM_KEY_TYPE_B +\
    A7X_CONFIG_COUNTER_TYPE_B +\
    A7X_CONFIG_GP_STORAGE_SECTION_TYPE_B)
#define A7X_CONFIG_KEY_PAIR_TYPE_B      4 //!< Actual amount of ECC key pairs that can be stored in A71CH
#define A7X_CONFIG_PUBLIC_KEY_TYPE_B    3 //!< Actual amount of ECC public keys that can be stored in A71CH
#define A7X_CONFIG_CFG_KEY_TYPE_B       3 //!< Actual amount of 128 bit configuration keys that can be stored in A71CH
#define A7X_CONFIG_SYM_KEY_TYPE_B       8 //!< Actual amount of 128 bit symmetric keys that can be stored in A71CH
#define A7X_CONFIG_COUNTER_TYPE_B       2 //!< Actual amount of monotonic counters that can be stored in A71CH
#define A7X_CONFIG_GP_STORAGE_SECTION_TYPE_B 128

#define A7X_CONFIG_CRED_INIT_MASK   0xF0
#define A7X_CONFIG_CRED_LOCK_MASK   0x0F
#define A7X_CONFIG_CRED_EMPTY       0xA0
#define A7X_CONFIG_CRED_INITIALIZED 0x50
#define A7X_CONFIG_CRED_LOCKED      0x0F
#define A7X_CONFIG_CRED_OPEN        0x05

typedef enum
{
    A71_KEY_PUB_PAIR = 0x10,
    A71_KEY_PUBLIC_KEY = 0x20
} a71_KeyTypeClass_t;

typedef enum
{
    A71_SSC_KEY_PAIR = 0x10,
    A71_SSC_PUBLIC_KEY = 0x20,
    A71_SSC_CONFIG_KEY = 0x30,
    A71_SSC_SYM_KEY = 0x40,
    A71_SSC_COUNTER = 0x60,
    A71_SSC_GP_DATA = 0x70,
    A71_SSC_MODULE = 0x90,
    A71_SSC_OBJECTS = 0xE0,
    A71_SSC_ALL = 0xFE,
    A71_SSC_UNDEF = 0xFF
} a71_SecureStorageClass_t;

typedef enum
{
    A71_OBJ_UPDATE = 0x10,
    A71_OBJ_WRITE = 0x20,
    A71_OBJ_READ = 0x30,
    A71_OBJ_ERASE = 0x40,
    A71_OBJ_ALL = 0x60,
    A71_OBJ_UNDEF = 0x70
} a71_ObjCmdClass_t;

typedef enum
{
    AX_SCP_CMD_AUTH = 0x01,
    AX_SCP_CMD_PUT = 0x02,
    AX_SCP_CMD_UNDEF = 0xFF
} ax_ScpCmdClass_t;

typedef struct
{
    U32 counter;
    U8 available;
} a71_CounterWrapper_t;

// Obj
// write
int a7xConfigCmdWriteObjFromSegments(int index, int segments, U16 *sw);
int a7xConfigCmdWriteObjFromfile(int index, char *szFilename, int chunkSize, a71_ObjCmdClass_t cmdType, U16 *sw);
U16 a7xConfigCmdWriteObj(int index, U8 * objData, U16 objDataLen, U16 *sw);
// update
int a7xConfigCmdUpdateObjFromfile(int index, int offset, char *szFilename, int chunkSize, a71_ObjCmdClass_t cmdType, U16 *sw);
int a7xConfigCmdUpdateObj(int index, int offset, U8 * objData, U16 objDataLen, U16 *sw);
// read
int a7xConfigCmdReadObj(int index, int offset, int length, int chunkSize, char *szFilename, U16 *sw);
// erase
int a7xConfigCmdEraseObj(int index, U16 *sw);

// Get
// pub
int a7xConfigCmdGetPub(int index, int type, char *szFilename, U16 *sw);

// Info
int a7xConfigCmdInfo(a71_SecureStorageClass_t ssc, U16 offset, int nSegments, U16 *sw);
int a7xCmdInfoDevicePrettyPrint(U8 *uid, U16 uidLen, U16 selectResponse, U8 debugOn, U8 restrictedKpIdx, U8 transportLockState, U8 scpState, U8 injectLockState, U16 gpStorageSize);
U16 a7xCmdInfoDevice(U8 *uid, U16 *uidLen, U16 *selectResponse, U8 *debugOn, U8 *restrictedKpIdx, U8 *transportLockState, U8 *scpState, U8 *injectLockState, U16 *gpStorageSize);
int a7xCmdInfoEccPrettyPrint(a71_SecureStorageClass_t ssc, int nEcc, eccKeyComponents_t *eccKc);
U16 a7xCmdInfoEcc(a71_SecureStorageClass_t ssc, int nEcc, eccKeyComponents_t *eccKc);
int a7xCmdInfoCounterPrettyPrint(int nCnt, a71_CounterWrapper_t *counterArray);
U16 a7xCmdInfoCounter(int nCnt, a71_CounterWrapper_t *counterArray);
int a7xCmdInfoGpDataPrettyPrint(U8 *data, U16 offset, int nSegments);
U16 a7xCmdInfoGpData(U8 *data, U16 dataLen, U16 offset);
int a7xConfigCmdInfoStatus(U16 *sw);
int a7xCmdInfoStatusPrettyPrint(U8 scp03Status, U8 *kpStatus, U16 kpStatusLen, U8 *pubStatus, U16 pubStatusLen, U8 *cfgStatus, U16 cfgStatusLen,
        U8 *symStatus, U16 symStatusLen, U8 *cntStatus, U16 cntStatusLen, U8 *gpStatus, U16 gpStatusLen);
U16 a7xCmdInfoStatus(U8 *scp03Status, U8 *kpStatus, U16 *kpStatusLen, U8 *pubStatus, U16 *pubStatusLen, U8 *cfgStatus, U16 *cfgStatusLen,
        U8 *symStatus, U16 *symStatusLen, U8 *cntStatus, U16 *cntStatusLen, U8 *gpStatus, U16 *gpStatusLen);

// apdu
int a7xConfigCmdApduSimple(U8 *cmd, U16 cmdLen, U16 swExpected, U16 *sw);
int a7xCmdApduPrettyPrint(U8 *cmd, U16 cmdLen, U8 *rsp, U16 rspLen);
U16 a7xCmdApdu(U8 *cmd, U16 cmdLen, U8 *rsp, U16 *rspLen);

// connect
int a7xConfigCmdConnectClose(U16 *sw);
U16 a7xCmdConnectClose();
int a7xConfigCmdConnectOpen(U16 *sw);
U16 a7xCmdConnectOpen(const char *connectString);

// Debug
int a7xConfigCmdDebugReset();
U16 a7xCmdDebugReset();
int a7xConfigCmdDebugDisable(U16 *sw);
U16 a7xCmdDebugDisable();

// Erase
int a7xConfigCmdEraseCredential(a71_SecureStorageClass_t ssc, U8 index, U16 *sw);
U16 a7xConfigEraseCredential(a71_SecureStorageClass_t ssc, U8 index);

// ecrt
int a7xConfigCmdEcrt(U8 index, U16 *sw);

// rcrt
int a7xConfigCmdRcrt(U8 index, char *szFilename, int szFilenameLen, U16 *sw);

// ucrt and wcrt
int a7xConfigCmdWcrt(U8 index, int update, U8 *crtData, U16 crtDataLen, int extraBytes, char *szFilename, int szFilenameLen, bool crtFile, U16 *sw);

// Gen
int a7xConfigCmdGen(U8 index, U16 *sw);
U16 a7xCmdGenEcc(U8 index);

// Lock
int a7xConfigCmdLockCredential(a71_SecureStorageClass_t ssc, U8 index, U16 *sw);
U16 a7xConfigLockCredential(a71_SecureStorageClass_t ssc, U8 index);
int a7xConfigCmdLockGp(U16 offset, int nSegments, U16 *sw);
U16 a7xConfigLockGp(U16 offset, U16 dataLen);
int a7xConfigCmdLockInjectPlain(U16 *sw);
U16 a7xConfigLockInjectPlain();

// Scp
int a7xConfigCmdScpFromKeyfile(ax_ScpCmdClass_t cmdClass, U8 keyVersion, char *szFilename, U16 *sw);
int a7xConfigGetScpKeysFromKeyfile(U8 *enc, U8 *mac, U8 *dek, char *szKeyFile);
int a7xConfigCmdScpClearHost();

// Set
int a7xConfigCmdSetGp(U16 offset, U8 *gpData, U16 gpDataLen, U16 *sw);
U16 a7xCmdSetGp(U16 offset, U8 *gpData, U16 gpDataLen);
int a7xConfigCmdSetGpFromPemfile(U16 offset, char *szFilename, U16 *sw);
// U16 a7xCmdSetGpFromPemFile(U16 offset, char *szFilename);
int a7xConfigCmdSetEcc(a71_SecureStorageClass_t ssc, U8 index, eccKeyComponents_t *eccKc, U16 *sw);
U16 a7xCmdSetEcc(a71_SecureStorageClass_t ssc, U8 index, eccKeyComponents_t *eccKc);
int a7xConfigCmdSetEccFromPemfile(a71_SecureStorageClass_t ssc, U8 index, char *szFilename, int argc, char ** argv, int *argCurrent, U16 *sw);
int a7xConfigGetEccKcFromPemfile(eccKeyComponents_t *eccKc, a71_SecureStorageClass_t ssc, const char *szKeyFile);
int a7xConfigCmdSetSym(U8 index, U8 *symSecret, U16 symSecretLen, U16 *sw);
U16 a7xCmdSetSym(U8 index, U8 *symSecret, U16 symSecretLen);
int a7xConfigCmdSetCnt(U8 index, U8 *cnt, U16 cntLen, U16 *sw);
U16 a7xCmdSetCnt(U8 index, U8 *cnt, U16 cntLen);
int a7xConfigCmdSetConfigKey(U8 index, U8 *configKey, U16 configKeyLen, U16 *sw);
U16 a7xCmdSetConfigKey(U8 index, U8 *configKey, U16 configKeyLen);
int a7xConfigCmdCheckWrapping(U8 * key, U16 * keyLen, int argc, char **argv, int * argCurrent);
U16 a7xCmdSetSymWrap(U8 index, U8 *symSecret, U16 symSecretLen, U8 * wrapKey, U16 wrapKeyLen);
int a7xConfigCmdSetSymWrap(U8 index, U8 *symSecret, U16 symSecretLen, U8 * wrapKey, U16 wrapKeyLen, U16 *sw);
int a7xConfigCmdSetEccWrap(a71_SecureStorageClass_t ssc, U8 index, eccKeyComponents_t *eccKc, U8 * wrapKey, U16 wrapKeyLen, U16 *sw);

// Transport
int a7xConfigCmdTransportLock(U16 *sw);
U16 a7xConfigTransportLock();
int a7xConfigCmdTransportUnlock(U8 *transportConfigKey, U16 transportConfigKeyLen, U16 *sw);
U16 a7xConfigTransportUnlock(U8 *transportConfigKey, U16 transportConfigKeyLen);

// Refpem (Creation of reference pem files)
int a7xConfigCmdRefpem(U8 storageClass, U8 keyIndex, const char *szKeyFile, const char *szRefKeyFile, U16 *sw);

#ifdef __cplusplus
}
#endif
#endif // _CONFIG_CMD_H_
