/**
* @file configCmdGet.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2018 NXP
* SPDX-License-Identifier: Apache-2.0
*
* @par Description
* Command handling for 'get'. Includes optional console handling
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
#include "configCmd.h"
#include "configCli.h"
#include "a71_debug.h"
#include "HLSEAPI.h"

#include "axHostCrypto.h"
#include "tstHostCrypto.h"

#ifdef OPENSSL
#include <openssl/pem.h>
#endif

#define FLOW_VERBOSE_PROBE_A70

#ifdef FLOW_VERBOSE_PROBE_A70
#define FPRINTF(...) printf (__VA_ARGS__)
#else
#define FPRINTF(...)
#endif

// Warning: defining DBG_PROBE_A70 also exposes Private Key being set in log
// #define DBG_PROBE_A70

#ifdef DBG_PROBE_A70
#define DBGPRINTF(...) printf (__VA_ARGS__)
#else
#define DBGPRINTF(...)
#endif

/**
* a7xConfigCmdGetPub - get public key from pub key or key pair and save it in PEM format to file
*/
int a7xConfigCmdGetPub(int index, int type, char *szFilename, U16 *sw) {
    HLSE_RET_CODE nRet = AX_CLI_EXEC_FAILED;
    eccKeyComponents_t eccKc;
    FILE * pFile = NULL;
    char *buff = NULL;
    EC_KEY *eckey = NULL;
    BIO *out = BIO_new(BIO_s_mem());
    BUF_MEM *bptr = NULL;
    unsigned char * pubuf;

    // Initialize data structure
    eccKc.bits = 256;
    eccKc.curve = ECCCurve_NIST_P256;
    eccKc.pubLen = sizeof(eccKc.pub);
    eccKc.privLen = sizeof(eccKc.priv);

    // Read public ECC key from card
    switch (type)
    {
    case A71_KEY_PUB_PAIR:
        *sw = A71_GetPublicKeyEccKeyPair((U8)index, eccKc.pub, &eccKc.pubLen);
        if (*sw != SW_OK) { return nRet; }
        break;
    case A71_KEY_PUBLIC_KEY:
        *sw = A71_GetEccPublicKey((U8)index, eccKc.pub, &eccKc.pubLen);
        if (*sw != SW_OK) { return nRet; }
        break;
    default:
        return nRet;
        break;
    }

    // Convert public key buffer to PEM format
    bptr = BUF_MEM_new();
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    pubuf = (unsigned char *) malloc(4096 * sizeof(unsigned char));
    memcpy(pubuf, eccKc.pub, (long)eccKc.pubLen);
    eckey = o2i_ECPublicKey(&eckey, (const unsigned char **)&pubuf, (long)eccKc.pubLen);
    PEM_write_bio_EC_PUBKEY(out, eckey);
    BIO_get_mem_ptr(out, &bptr);
    BIO_set_close(out, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    buff = (char *)malloc(bptr->length);        //converting BUF_MEM  to Char *
    if (buff == NULL) {
        BIO_free_all(out);
        return AX_CLI_DYN_ALLOC_ERROR;
    }
    memcpy(buff, bptr->data, bptr->length - 1);         //to be used later
    buff[bptr->length - 1] = 0;
    BIO_free_all(out);

    // Save PEM file to buffer
    pFile = fopen(szFilename, "w");
    if (pFile) {
        fwrite(buff, bptr->length-1, 1, pFile);
        free(buff);
        fclose(pFile);
    }
    else {
        free(buff);
        return AX_CLI_EXEC_FAILED;
    }

    return AX_CLI_EXEC_OK;
}
