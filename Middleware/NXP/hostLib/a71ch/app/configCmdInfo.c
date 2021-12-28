/**
 * @file configCmdInfo.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * Command handling for 'info'. Includes optional console print.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef OPENSSL
#include <openssl/pem.h>
#endif

// project specific include files
#include "sm_types.h"
#include "sm_apdu.h"
#include "tst_sm_util.h"
#include "tst_a71ch_util.h"
#include "probeAxUtil.h"
#include "configCmd.h"
#include "configCli.h" // Used for error codes.
#include "configState.h"
#include "HLSETypes.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#include "HLSEAPI.h"

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

#define HLSE_GP_DATA_CHUNK              32      //!< GP Data chunk size byted

/// GP Table Data Entry
typedef struct {
    U8      klass;
    U8      index;
    U16     length;
    U16     offset;
} HLSE_GP_DATA_TABLE_ENTRY;

#define HLSE_GP_DATA_TABLE_ENTRY_SIZE   6   //!< GP Table Entry size in bytes

/// Alligned number of chunks in which 'size' bytes occupies
#define HLSE_ALIGN_SIZE(size)           ((size + HLSE_GP_DATA_CHUNK - 1) / HLSE_GP_DATA_CHUNK)

// This is a theoritical max , as it is stored as one byte in the beginning of the Gp Table - up to max 254 entries (0xFE)
// elements might be created .  value of 0xFF is reserved for a deleted/invalid entry
#define HLSE_MAX_OBJECTS_IN_TABLE 254

// Max chunks which could be allowed in GP Data table
#define HLSE_GP_DATA_CHUNKS_NUM HLSE_ALIGN_SIZE(((HLSE_MAX_OBJECTS_IN_TABLE * 6) + 2))

/// GP Data Table
typedef struct {
    U8                          numOfEntries;                       //!< num of entries
    U8                          updateCounter;                      //!< update counter
    HLSE_GP_DATA_TABLE_ENTRY    entries[HLSE_MAX_OBJECTS_IN_TABLE]; //!< entries array
} HLSE_GP_DATA_TABLE;

static HLSE_RET_CODE DisplayObjectInfo();

/**
 * A hook for the command line handler to invoke A71 commands
 * \return Returns ::AX_CLI_EXEC_OK upon success
 */
int a7xConfigCmdInfo(a71_SecureStorageClass_t ssc, U16 offset, int nSegments, U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    U8 uid[A71CH_MODULE_UNIQUE_ID_LEN];
    U16 uidLen = sizeof(uid);

    U16 selectResponse = 0;
    U8 debugOn = 0;
    U8 restrictedKpIdx = 0;
    U8 transportLockState = 0;
    U8 scpState = A71CH_SCP_CHANNEL_STATE_UNKNOWN;
    U8 injectLockState = 0;
    U16 gpStorageSize = 0;
    int nEccPair = 0;
    int nEccPub = 0;
    int nCnt = 0;
    // int nSymKey = 0;
    int nGpSections = 0;

    // TODO: Recognize whether SCP03 has already been set up by the config tool. (Store this state in scpReq - to be renamed in scpChannelActive)
    *sw = a7xCmdInfoDevice(uid, &uidLen, &selectResponse, &debugOn, &restrictedKpIdx, &transportLockState, &scpState, &injectLockState, &gpStorageSize);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
        if ( (ssc == A71_SSC_MODULE) || (ssc == A71_SSC_ALL) )
        {
            a7xCmdInfoDevicePrettyPrint(uid, uidLen, selectResponse, debugOn, restrictedKpIdx, transportLockState, scpState, injectLockState, gpStorageSize);
        }
    }
    else
    {
        error = AX_CLI_EXEC_FAILED;
        return error;
    }

    if (gpStorageSize == 1024) {
        nEccPair = A7X_CONFIG_KEY_PAIR_TYPE_A;
        nEccPub = A7X_CONFIG_PUBLIC_KEY_TYPE_A;
        nCnt = A7X_CONFIG_COUNTER_TYPE_A;
        // nSymKey = A7X_CONFIG_SYM_KEY_TYPE_A;
        nGpSections = A7X_CONFIG_GP_STORAGE_SECTION_TYPE_A;
    }
    else if (gpStorageSize == 4096) {
        nEccPair = A7X_CONFIG_KEY_PAIR_TYPE_B;
        nEccPub = A7X_CONFIG_PUBLIC_KEY_TYPE_B;
        nCnt = A7X_CONFIG_COUNTER_TYPE_B;
        // nSymKey = A7X_CONFIG_SYM_KEY_TYPE_B;
        nGpSections = A7X_CONFIG_GP_STORAGE_SECTION_TYPE_B;
    }
    else {
        // Defaulting to smallest credential set
        printf("Warning: Tool does not know exact amount of credentials stored. Using default values.\n");
        nEccPair = A7X_CONFIG_KEY_PAIR_TYPE_A;
        nEccPub = A7X_CONFIG_PUBLIC_KEY_TYPE_A;
        nCnt = A7X_CONFIG_COUNTER_TYPE_A;
        // nSymKey = A7X_CONFIG_SYM_KEY_TYPE_A;
        nGpSections = A7X_CONFIG_GP_STORAGE_SECTION_TYPE_A;
    }

    if ( (scpState != A71CH_SCP_MANDATORY) ||
         ((scpState == A71CH_SCP_MANDATORY) && (a7xConfigGetHostScp03State() == AX_SCP03_CHANNEL_ON)) )
    {
        eccKeyComponents_t eccKc[(A7X_CONFIG_KEY_PAIR_MAX > A7X_CONFIG_PUBLIC_KEY_MAX) ? A7X_CONFIG_KEY_PAIR_MAX : A7X_CONFIG_PUBLIC_KEY_MAX];
        a71_CounterWrapper_t counterArray[A7X_CONFIG_COUNTER_MAX];
        U8 data[A7X_CONFIG_GP_STORAGE_MAX];
        U16 dataLen = sizeof(data);

        // Only in this case can we query for the value of credentials
        switch (ssc)
        {
        case A71_SSC_KEY_PAIR:
            a7xCmdInfoEcc(ssc, nEccPair, eccKc);
            error = a7xCmdInfoEccPrettyPrint(ssc, nEccPair, eccKc);
            break;

        case A71_SSC_PUBLIC_KEY:
            a7xCmdInfoEcc(ssc, nEccPub, eccKc);
            error = a7xCmdInfoEccPrettyPrint(ssc, nEccPub, eccKc);
            break;

        case A71_SSC_COUNTER:
            a7xCmdInfoCounter(nCnt, counterArray);
            error = a7xCmdInfoCounterPrettyPrint(nCnt, counterArray);
            break;

        case A71_SSC_OBJECTS:
            error = DisplayObjectInfo();
            break;

        case A71_SSC_GP_DATA:
            if ( (U16)(nSegments * A71CH_GP_STORAGE_GRANULARITY) > dataLen ) {
                error = AX_CLI_BUFFER_SIZE_ERROR;
            }
            dataLen = (U16)(nSegments * A71CH_GP_STORAGE_GRANULARITY);
            *sw = a7xCmdInfoGpData(data, dataLen, offset);
            if (*sw == SW_OK) {
                error = a7xCmdInfoGpDataPrettyPrint(data, offset, nSegments);
            }
            else {
                printf("Could not retrieve data from gp storage.\n");
                error = AX_CLI_EXEC_FAILED;
            }
            break;

        case A71_SSC_CONFIG_KEY:
        case A71_SSC_SYM_KEY:
            printf("Not implemented.\n");
            error = AX_CLI_NOT_IMPLEMENTED;
            break;

        case A71_SSC_ALL:
            a7xCmdInfoEcc(A71_SSC_KEY_PAIR, nEccPair, eccKc);
            error = a7xCmdInfoEccPrettyPrint(A71_SSC_KEY_PAIR, nEccPair, eccKc);
            a7xCmdInfoEcc(A71_SSC_PUBLIC_KEY, nEccPub, eccKc);
            error = a7xCmdInfoEccPrettyPrint(A71_SSC_PUBLIC_KEY, nEccPub, eccKc);
            a7xCmdInfoCounter(nCnt, counterArray);
            error = a7xCmdInfoCounterPrettyPrint(nCnt, counterArray);
            *sw = a7xCmdInfoGpData(data, (U16)(nGpSections * A71CH_GP_STORAGE_GRANULARITY), 0);
            if (*sw == SW_OK) {
                error = a7xCmdInfoGpDataPrettyPrint(data, 0, nGpSections);
            }
            else {
                printf("Could not retrieve data from gp storage.\n");
                error = AX_CLI_EXEC_FAILED;
            }
            break;

        case A71_SSC_MODULE:
            // No action required
            break;

        case A71_SSC_UNDEF:
            printf("Undefined Secure Storage Class.\n");
            error = AX_CLI_ARG_VALUE_ERROR;
            break;
        }
    }
    else
    {
        // As we don't know the SCP03 keys - conditionally - display a warning on the console.
        switch (ssc)
        {
        case A71_SSC_KEY_PAIR:
        case A71_SSC_PUBLIC_KEY:
        case A71_SSC_GP_DATA:
        case A71_SSC_OBJECTS:
        case A71_SSC_CONFIG_KEY:
        case A71_SSC_SYM_KEY:
        case A71_SSC_COUNTER:
        case A71_SSC_ALL:
            printf("info command needs prior setup of SCP03 channel.\n");
            printf("Debug: a7xConfigGetHostScp03State() = 0x%02X\n", a7xConfigGetHostScp03State());
            error = AX_CLI_EXEC_FAILED;
            break;

        case A71_SSC_MODULE:
            // No action required
            break;

        case A71_SSC_UNDEF:
            printf("Undefined Secure Storage Class.\n");
            error = AX_CLI_ARG_VALUE_ERROR;
            break;
        }
    }
    return error;
}


/**
 * Print to console
 */
int a7xCmdInfoDevicePrettyPrint(U8 *uid, U16 uidLen, U16 selectResponse, U8 debugOn, U8 restrictedKpIdx, U8 transportLockState, U8 scpState, U8 injectLockState, U16 gpStorageSize)
{
    int idx = 0;
    U8 certUid[A71CH_MODULE_CERT_UID_LEN];

    printf("A71CH in %s (%s)\n",
        (debugOn == 0) ? "Production Version" : "Debug Mode Version",
        (scpState == A71CH_SCP_MANDATORY) ? "SCP03 is mandatory" :
        (scpState == A71CH_SCP_NOT_SET_UP) ? "SCP03 is not set up" :
        (scpState == A71CH_SCP_KEYS_SET) ? "SCP03 keys set" : "Undefined SCP state");
    printf("selectResponse:   0x%04X\n", selectResponse);
    if (restrictedKpIdx != A71CH_NO_RESTRICTED_KP)
    {
        printf("restricted keypair index: 0x%02X\n", restrictedKpIdx);
    }
    printf("transportLockState: 0x%02X (%s)\n", transportLockState,
            (transportLockState == A71CH_TRANSPORT_LOCK_STATE_LOCKED) ? "Transport Lock is set" :
            (transportLockState == A71CH_TRANSPORT_LOCK_STATE_UNLOCKED) ? "Open device, Transport Lock can no longer be set" :
            (transportLockState == A71CH_TRANSPORT_LOCK_STATE_ALLOW_LOCK) ? "Transport Lock NOT YET set" : "Undefined Transport Lock state");
    printf("injectLockState:    0x%02X (%s)\n", injectLockState,
            (injectLockState == A71CH_INJECT_LOCK_STATE_LOCKED) ? "Locked" :
            (injectLockState == A71CH_INJECT_LOCK_STATE_UNLOCKED) ? "Unlocked" : "Undefined Inject Lock State");
    printf("gpStorageSize:      %d\n", gpStorageSize);
    axPrintByteArray("uid", uid, uidLen, AX_COLON_32);


    certUid[idx++] = uid[A71CH_UID_IC_TYPE_OFFSET];
    certUid[idx++] = uid[A71CH_UID_IC_TYPE_OFFSET+1];
    certUid[idx++] = uid[A71CH_UID_IC_FABRICATION_DATA_OFFSET];
    certUid[idx++] = uid[A71CH_UID_IC_FABRICATION_DATA_OFFSET+1];
    certUid[idx++] = uid[A71CH_UID_IC_SERIAL_NR_OFFSET];
    certUid[idx++] = uid[A71CH_UID_IC_SERIAL_NR_OFFSET+1];
    certUid[idx++] = uid[A71CH_UID_IC_SERIAL_NR_OFFSET+2];
    certUid[idx++] = uid[A71CH_UID_IC_BATCH_ID_OFFSET];
    certUid[idx++] = uid[A71CH_UID_IC_BATCH_ID_OFFSET+1];
    certUid[idx++] = uid[A71CH_UID_IC_BATCH_ID_OFFSET+2];

    axPrintByteArray("certUid", certUid, (U16)idx, AX_COLON_32);

    return AX_CLI_EXEC_OK;
}

/**
 * API wrapper for info command. Can be called from GUI.
 */
U16 a7xCmdInfoDevice(U8 *uid, U16 *uidLen, U16 *selectResponse, U8 *debugOn, U8 *restrictedKpIdx, U8 *transportLockState, U8 *scpState, U8 *injectLockState, U16 *gpStorageSize)
{
    U16 sw;

    *selectResponse = 0x0000;
    *debugOn = 0x00;
    *restrictedKpIdx = 0x00;
    *injectLockState = 0x00;
    *gpStorageSize = 0x0000;
    *scpState = A71CH_SCP_CHANNEL_STATE_UNKNOWN;

    sw = A71_GetModuleInfo(selectResponse, debugOn, restrictedKpIdx, transportLockState, scpState, injectLockState, gpStorageSize);

    // Retrieving UID can be protected by SCP03
    if ( (*uidLen != 0) && (uid != NULL) && (sw == SW_OK) )
    {
        sw = A71_GetUniqueID(uid, uidLen);
        if (sw != SW_OK)
        {
            DBGPRINTF("Failed to retrieve UID.\n");
        }
    }

    return sw;
}


/**
 * Print Public key to console
 */
int a7xCmdInfoEccPrettyPrint(a71_SecureStorageClass_t ssc, int nEcc, eccKeyComponents_t *eccKc)
{
    int i = 0;

    if (ssc == A71_SSC_KEY_PAIR) {
        printf("Public Keys from ECC key pairs:\n");
    }
    else if (ssc == A71_SSC_PUBLIC_KEY) {
        printf("Public Keys:\n");
    }
    else {
        printf("Wrong ssc requested: 0x%02X\n", ssc);
        return AX_CLI_API_ERROR;
    }

    for (i=0; i<nEcc; i++)
    {
        printf("\tidx=0x%02X ", i);
        if (eccKc[i].pubLen > 0) {
            axPrintByteArray("ECC_PUB", eccKc[i].pub, eccKc[i].pubLen, AX_COLON_32);
        }
        else {
            printf("n.a.\n");
        }
    }

    return AX_CLI_EXEC_OK;
}

/**
 * API wrapper for info command. Can be called from GUI.
 */
U16 a7xCmdInfoEcc(a71_SecureStorageClass_t ssc, int nEcc, eccKeyComponents_t *eccKc)
{
    U16 sw = SW_OK;
    int i = 0;

    // Initialize data structures.
    for (i=0; i<nEcc; i++)
    {
        eccKc[i].bits = 256;
        eccKc[i].curve = ECCCurve_NIST_P256;
        eccKc[i].pubLen = sizeof(eccKc[i].pub);
        eccKc[i].privLen = sizeof(eccKc[i].priv);
    }

    for (i=0; i<nEcc; i++)
    {
        switch (ssc)
        {
            case A71_SSC_KEY_PAIR:
                sw = A71_GetPublicKeyEccKeyPair((U8)i, eccKc[i].pub, &(eccKc[i].pubLen));
                if (sw != SW_OK) { eccKc[i].pubLen = 0; }
                break;
            case A71_SSC_PUBLIC_KEY:
                sw = A71_GetEccPublicKey((U8)i, eccKc[i].pub, &(eccKc[i].pubLen));
                if (sw != SW_OK) { eccKc[i].pubLen = 0; }
                break;
            default:
                eccKc[i].pubLen = 0;
                break;
        }
    }
    // We always claim success for the overall operation.
    // In case a specific public key could not be retrieved, its length has been set to zero
    return SW_OK;
}

int a7xCmdInfoCounterPrettyPrint(int nCnt, a71_CounterWrapper_t *counterArray)
{
    int i = 0;

    printf("Monotonic counter values:\n");
    for (i=0; i<nCnt; i++)
    {
        printf("\tidx=0x%02X ", i);
        if (counterArray[i].available == 0x01) {
            printf("0x%08X\n", counterArray[i].counter);
        }
        else {
            printf("n.a.\n");
        }
    }

    return AX_CLI_EXEC_OK;
}

U16 a7xCmdInfoCounter(int nCnt, a71_CounterWrapper_t *counterArray)
{
    U16 sw = SW_OK;
    int i = 0;

    // Initialize data structures.
    for (i=0; i<nCnt; i++)
    {
        counterArray[i].available = 0x00;
        counterArray[i].counter = 0;
    }

    for (i=0; i<nCnt; i++)
    {
        sw = A71_GetCounter((U8)i, &(counterArray[i].counter));
        if (sw == SW_OK)
        {
            counterArray[i].available = 0x01;
        }
    }
    // We always claim success for the overall operation.
    // In case a specific counter value could not be retrieved, its available field will be set to 0x00
    return SW_OK;
}

int a7xCmdInfoGpDataPrettyPrint(U8 *data, U16 offset, int nSegments)
{
    int i = 0;
    char szOffset[64];

    printf("GP Storage Data (%d segments from offset 0x%04X):\n", nSegments, offset);
    for (i=0; i<nSegments; i++)
    {
        sprintf(szOffset, "\t0x%04X", offset + (i*A71CH_GP_STORAGE_GRANULARITY));
        axPrintByteArray(szOffset, data+(i*A71CH_GP_STORAGE_GRANULARITY), A71CH_GP_STORAGE_GRANULARITY, AX_COMPACT_LINE);
    }

    return AX_CLI_EXEC_OK;
}

U16 a7xCmdInfoGpData(U8 *data, U16 dataLen, U16 offset)
{
    U16 sw;

    sw = A71_GetGpData(offset, data, dataLen);

    return sw;
}

// ---

/**
 * A hook for the command line handler to invoke A71 commands
 */
int a7xConfigCmdInfoStatus(U16 *sw)
{
    int error = AX_CLI_EXEC_FAILED;

    U8 scp03Status = 0x00;
    U8 kpStatus[A7X_CONFIG_KEY_PAIR_MAX];
    U16 kpStatusLen = sizeof(kpStatus);
    U8 pubStatus[A7X_CONFIG_PUBLIC_KEY_MAX];
    U16 pubStatusLen = sizeof(pubStatus);
    U8 cfgStatus[A7X_CONFIG_CFG_KEY_MAX];
    U16 cfgStatusLen = sizeof(cfgStatus);
    U8 symStatus[A7X_CONFIG_SYM_KEY_MAX];
    U16 symStatusLen = sizeof(symStatus);
    U8 cntStatus[A7X_CONFIG_COUNTER_MAX];
    U16 cntStatusLen = sizeof(cntStatus);
    U8 gpStatus[A7X_CONFIG_GP_STORAGE_SECTION_MAX];
    U16 gpStatusLen = sizeof(gpStatus);

    // U16 selectResponse = 0;
    // U8 debugOn = 0;
    // U8 injectLockState = 0;
    // U16 gpStorageSize = 0;

    *sw = a7xCmdInfoStatus(&scp03Status, kpStatus, &kpStatusLen, pubStatus, &pubStatusLen, cfgStatus, &cfgStatusLen,
        symStatus, &symStatusLen, cntStatus, &cntStatusLen, gpStatus, &gpStatusLen);
    if (*sw == SW_OK)
    {
        error = AX_CLI_EXEC_OK;
        a7xCmdInfoStatusPrettyPrint(scp03Status, kpStatus, kpStatusLen, pubStatus, pubStatusLen, cfgStatus, cfgStatusLen,
            symStatus, symStatusLen, cntStatus, cntStatusLen, gpStatus, gpStatusLen);
    }
    return error;
}

static int a7xCmdInfoStatusCredStatusPrettyPrint(char *szObjectName, U8 *statusArray, U16 arrayLen)
{
    int i;

    printf("%s status:\n", szObjectName);
    for (i=0; i<arrayLen; i++)
    {
        printf("\tIndex=%d: %s %s\n", i,
            ((statusArray[i] & A7X_CONFIG_CRED_INIT_MASK) == A7X_CONFIG_CRED_INITIALIZED) ? "Initialized" : "Empty",
            ((statusArray[i] & A7X_CONFIG_CRED_LOCK_MASK) == A7X_CONFIG_CRED_LOCKED) ? "Locked" : "Open");
    }
    return AX_CLI_EXEC_OK;
}

static int a7xCmdInfoStatusGpStatusPrettyPrint(char *szObjectName, U8 *statusArray, U16 arrayLen)
{
    int i;
    int nColumns = 4;

    printf("%s status:\n", szObjectName);
    for (i=0; i<arrayLen; i++)
    {
        printf("\tOffset=0x%04X: %s%s", i * A71CH_GP_STORAGE_GRANULARITY,
            ((statusArray[i] & A7X_CONFIG_CRED_LOCK_MASK) == A7X_CONFIG_CRED_LOCKED) ? "Lock" : "Open",
            (((i+1) % nColumns) == 0) ? "\n" : "   ");
    }
    return AX_CLI_EXEC_OK;
}

/**
 * Print to console
 */
int a7xCmdInfoStatusPrettyPrint(U8 scp03Status, U8 *kpStatus, U16 kpStatusLen, U8 *pubStatus, U16 pubStatusLen, U8 *cfgStatus, U16 cfgStatusLen,
    U8 *symStatus, U16 symStatusLen, U8 *cntStatus, U16 cntStatusLen, U8 *gpStatus, U16 gpStatusLen)
{
    printf("SCP03 is %s\n", (scp03Status == A71CH_SCP_MANDATORY) ? "Mandatory" : "Not enabled");
    a7xCmdInfoStatusCredStatusPrettyPrint("Key Pair", kpStatus, kpStatusLen);
    a7xCmdInfoStatusCredStatusPrettyPrint("Public Key", pubStatus, pubStatusLen);
    a7xCmdInfoStatusCredStatusPrettyPrint("Config Key", cfgStatus, cfgStatusLen);
    a7xCmdInfoStatusCredStatusPrettyPrint("Sym Secret", symStatus, symStatusLen);
    a7xCmdInfoStatusCredStatusPrettyPrint("Counter", cntStatus, cntStatusLen);
    a7xCmdInfoStatusGpStatusPrettyPrint("General Purpose Storage", gpStatus, gpStatusLen);

    return AX_CLI_EXEC_OK;
}

/**
 * API wrapper for debug info command. Can be called from GUI.
 */
U16 a7xCmdInfoStatus(U8 *scp03Status, U8 *kpStatus, U16 *kpStatusLen, U8 *pubStatus, U16 *pubStatusLen, U8 *cfgStatus, U16 *cfgStatusLen,
    U8 *symStatus, U16 *symStatusLen, U8 *cntStatus, U16 *cntStatusLen, U8 *gpStatus, U16 *gpStatusLen)
{
    U16 sw;
    U8 map[A71CH_MAP_SIZE_MAX];
    U16 mapLen = sizeof(map);

    int kpStatusOffset = 1;
    int kpStatusN;
    int pubStatusOffset;
    int pubStatusN;
    int cfgStatusOffset;
    int cfgStatusN;
    int symStatusOffset;
    int symStatusN;
    int cntStatusOffset;
    int cntStatusN;
    int gpStatusOffset;
    int gpStatusN;

    sw = A71_GetCredentialInfo(map, &mapLen);

    if (sw == SW_OK)
    {
        switch (mapLen)
        {
        case A7X_CONFIG_MAP_SIZE_A71CH_TYPE_A:
            kpStatusN = A7X_CONFIG_KEY_PAIR_TYPE_A;
            pubStatusOffset = kpStatusOffset + kpStatusN;
            pubStatusN = A7X_CONFIG_PUBLIC_KEY_TYPE_A;
            cfgStatusOffset = pubStatusOffset + pubStatusN;
            cfgStatusN = A7X_CONFIG_CFG_KEY_TYPE_A;
            symStatusOffset = cfgStatusOffset + cfgStatusN;
            symStatusN = A7X_CONFIG_SYM_KEY_TYPE_A;
            cntStatusOffset = symStatusOffset + symStatusN;
            cntStatusN = A7X_CONFIG_COUNTER_TYPE_A;
            gpStatusOffset = cntStatusOffset + cntStatusN;
            gpStatusN = A7X_CONFIG_GP_STORAGE_SECTION_TYPE_A;
            break;

        case A7X_CONFIG_MAP_SIZE_A71CH_TYPE_B:
            kpStatusN = A7X_CONFIG_KEY_PAIR_TYPE_B;
            pubStatusOffset = kpStatusOffset + kpStatusN;
            pubStatusN = A7X_CONFIG_PUBLIC_KEY_TYPE_B;
            cfgStatusOffset = pubStatusOffset + pubStatusN;
            cfgStatusN = A7X_CONFIG_CFG_KEY_TYPE_B;
            symStatusOffset = cfgStatusOffset + cfgStatusN;
            symStatusN = A7X_CONFIG_SYM_KEY_TYPE_B;
            cntStatusOffset = symStatusOffset + symStatusN;
            cntStatusN = A7X_CONFIG_COUNTER_TYPE_B;
            gpStatusOffset = cntStatusOffset + cntStatusN;
            gpStatusN = A7X_CONFIG_GP_STORAGE_SECTION_TYPE_B;
            break;

        default:
            // Unknown product variant
            DBGPRINTF("Unknown mapLen: %d.", mapLen);
            return ERR_WRONG_RESPONSE;
            break;
        }

        *scp03Status = map[0];
        if (*kpStatusLen < kpStatusN) { return ERR_BUF_TOO_SMALL; }
        if (*pubStatusLen < pubStatusN) { return ERR_BUF_TOO_SMALL; }
        if (*cfgStatusLen < cfgStatusN) { return ERR_BUF_TOO_SMALL; }
        if (*symStatusLen < symStatusN) { return ERR_BUF_TOO_SMALL; }
        if (*cntStatusLen < cntStatusN) { return ERR_BUF_TOO_SMALL; }
        if (*gpStatusLen < gpStatusN) { return ERR_BUF_TOO_SMALL; }

        memcpy(kpStatus, &map[kpStatusOffset], kpStatusN);
        memcpy(pubStatus, &map[pubStatusOffset], pubStatusN);
        memcpy(cfgStatus, &map[cfgStatusOffset], cfgStatusN);
        memcpy(symStatus, &map[symStatusOffset], symStatusN);
        memcpy(cntStatus, &map[cntStatusOffset], cntStatusN);
        memcpy(gpStatus, &map[gpStatusOffset], gpStatusN);

        *kpStatusLen = (U16)kpStatusN;
        *pubStatusLen = (U16)pubStatusN;
        *cfgStatusLen = (U16)cfgStatusN;
        *symStatusLen = (U16)symStatusN;
        *cntStatusLen = (U16)cntStatusN;
        *gpStatusLen = (U16)gpStatusN;
    }

    return sw;
}


static HLSE_RET_CODE GetGPDataSize(U16* gpSize)
{
    HLSE_RET_CODE lReturn = HLSE_SW_OK;

    // Get the Module's handle
    HLSE_OBJECT_HANDLE modHandle = 0;
    //U16 modHandleNum = 1;

    modHandle = HLSE_CREATE_HANDLE(1, HLSE_MODULE, 0);

    {
        HLSE_ATTRIBUTE attr;
        attr.type = HLSE_ATTR_MODULE_TOTAL_GP_SIZE;
        attr.value = gpSize;
        attr.valueLen = sizeof(U16);

        lReturn = HLSE_GetObjectAttribute(modHandle, &attr);
    }

    return lReturn;
}


static HLSE_RET_CODE ParseGPDataTable(HLSE_GP_DATA_TABLE* table)
{
    // NOTE: only one chunk is read. To be updated if a table with more than 5 objects is used

    U16 gpSize;
    HLSE_RET_CODE lReturn = HLSE_SW_OK;
    U8 dataRead[HLSE_GP_DATA_CHUNK * HLSE_GP_DATA_CHUNKS_NUM];
    U8 entryNum;

    U16 dataReadByteSize = sizeof(dataRead);
    int nObj;
    U8 bValidEntry;
    U8 nMaxObj;
    U8 tmpClass, tmpIndex;

    lReturn = GetGPDataSize(&gpSize);
    if (lReturn != HLSE_SW_OK)
        return lReturn;

    memset(table, 0xFF, sizeof(HLSE_GP_DATA_TABLE));
    table->numOfEntries = 0;
    table->updateCounter = 0;

    // Read the entire table
    lReturn = A71_GetGpData(gpSize - dataReadByteSize, dataRead, dataReadByteSize);
    if (lReturn != HLSE_SW_OK)
        return lReturn;

    table->numOfEntries = dataRead[dataReadByteSize - 1];
    if (table->numOfEntries == 0xFF) {
        return HLSE_SW_OK;
    }

    table->updateCounter = dataRead[dataReadByteSize - 2];

    // Read only Valid entries up to numOfEntries starting from end of GP storage ( high address to low address )
    nObj = 1; // first object to check if valid in GP Table
    for (entryNum = 0; entryNum < table->numOfEntries; ++entryNum) {
        //  Notes:
        //      X + 1 is the address of the last byte of the GP Storage.
        //      N is the object number from 1 to N

        // read from object 1 to numOfEntries (skipping invalid =(deleted) entries)

        /*
        Address     Value
        -------     ----------------------
        X-N*6+0     N'th Object Class       - 1 byte
        X-N*6+1     N'th Object Index       - 1 byte
        X-N*6+2     N'th Object Length MSB  - 1 byte
        X-N*6+3     N'th Object Length LSB  - 1 byte
        X-N*6+4     N'th Object Offset MSB  - 1 byte
        X-N*6+5     N'th Object Offset LSB  - 1 byte
        */

        bValidEntry = 0;
        // max objects that could be held in the gp data table
        nMaxObj = HLSE_MAX_OBJECTS_IN_TABLE; //((HLSE_GP_DATA_CHUNK * HLSE_GP_DATA_CHUNKS_NUM) - 2) / 6;

        while (!bValidEntry && nObj <= nMaxObj) {
            // check if entry is valid
            tmpClass = dataRead[dataReadByteSize - 2 - nObj * 6 + 0];
            tmpIndex = dataRead[dataReadByteSize - 2 - nObj * 6 + 1];

            // skip to next valid entry
            if (tmpClass != 0xFF && tmpIndex != 0xFF) {
                // this is a valid entry
                bValidEntry = 1;
                break;
            }
        }

        if (!bValidEntry) {
            // error - no more valid entries in table , although num of entries in gp table says there are more !
            break;
        }

        // fill this valid entry in our table
        table->entries[entryNum].klass = dataRead[dataReadByteSize - 2 - nObj * 6 + 0];
        table->entries[entryNum].index = dataRead[dataReadByteSize - 2 - nObj * 6 + 1];
        table->entries[entryNum].length = dataRead[dataReadByteSize - 2 - nObj * 6 + 2] * 256 | dataRead[dataReadByteSize - 2 - nObj * 6 + 3];
        table->entries[entryNum].offset = dataRead[dataReadByteSize - 2 - nObj * 6 + 4] * 256 | dataRead[dataReadByteSize - 2 - nObj * 6 + 5];

        nObj++;
    }

    // sort the entries in ascending order of the offset
    //    SortTable(table);

    return lReturn;
}

static HLSE_RET_CODE PrintObjectInfo(HLSE_OBJECT_TYPE objType, HLSE_GP_DATA_TABLE* gpTable)
{
    HLSE_RET_CODE ret;
    HLSE_OBJECT_HANDLE handles[HLSE_MAX_OBJECTS_IN_TABLE];
    U16 handlesNum = HLSE_MAX_OBJECTS_IN_TABLE;
    U16 i, j;

    ret = HLSE_EnumerateObjects(objType, handles, &handlesNum);
    if (ret != HLSE_SW_OK)
        return ret;

    printf("%s Objects: \n", (objType == HLSE_CERTIFICATE ? "Certificate" : "Data"));
    for (i = 0; i < handlesNum; ++i) {
        HLSE_OBJECT_INDEX index;

        // get object index from applet
        {
            HLSE_ATTRIBUTE attr;
            attr.type = HLSE_ATTR_OBJECT_INDEX;
            attr.value = &index;
            attr.valueLen = sizeof(index);

            ret = HLSE_GetObjectAttribute(handles[i], &attr);
            if (ret != HLSE_SW_OK)
                return ret;
        }

        for (j = 0; j < gpTable->numOfEntries; ++j) {
            if (gpTable->entries[j].index == index && gpTable->entries[j].klass == HLSE_GET_LOGICAL_OBJECT_CLASS(objType)) {
                printf("\t idx=0x%02X Absolute offset = 0x%04X Actual Size = 0x%04X (%d)\n", index,
                    gpTable->entries[j].offset,
                    gpTable->entries[j].length,
                    gpTable->entries[j].length);
            }
        }
    }

    return ret;
}

static HLSE_RET_CODE DisplayObjectInfo()
{
    HLSE_GP_DATA_TABLE gpTable;
    HLSE_RET_CODE ret = HLSE_SW_OK;

    // Read the mapping table
    ret = ParseGPDataTable(&gpTable);
    if (ret != HLSE_SW_OK)
        return ret;

    // enumerate Cert + Data objects
    ret = PrintObjectInfo(HLSE_CERTIFICATE, &gpTable);
    if (ret != HLSE_SW_OK)
        return ret;

    ret = PrintObjectInfo(HLSE_DATA, &gpTable);
    if (ret != HLSE_SW_OK)
        return ret;

    return AX_CLI_EXEC_OK;
}
