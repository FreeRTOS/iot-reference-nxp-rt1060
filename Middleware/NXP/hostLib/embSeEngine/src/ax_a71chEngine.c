/**
 * @file ax_a71chEngine.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017,2020 NXP
 * SPDX-License-Identifier: Apache-2.0
 *
 * @par Description
 * OpenSSL Engine for Embedded Secure Element (A71CH)
 *
 * This engine invokes the API of axHostSw/a71ch that wraps APDU communication
 * with the A71CH secure element.
 *
 * The following operations are supported by this engine:
 * - Random number generation
 * - ECC sign
 * - ECC verify
 * - ECDH compute_key
 *
 * When dealing with an EC key argument whose a public key is used:
 * - In case the key is a 'reference key' -> use the referenced public key
 * - In case the public key is passed by value and it matches the value of a public key
 *   stored in the Secure Element -> delegate the operation to the Secure Element
 * - If none of the two above cases apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * When dealing with an EC key argument whose private key is used:
 * - In case the key is a 'reference key' -> use the referenced private key
 * - In case the above does not apply; at compile time one can choose between two
 *   strategies:
 *   (1) return a fail
 *   (2) delegate the operation to the OpenSSL SW implementation
 *
 * @note
 *   Compatible with:
 *   - OpenSSL 1.0.2
 *   - OpenSSL 1.1.0
 *
 */

/*
 * This file contains source code form OpenSSL distribution that is covered
 * by the LICENSE-OpenSSL file to be found in the root of this source code
 * distribution tree.
 */

#include "ax_embSeEngine.h"
#include "ax_cryptoIpc.h"
#include <openssl/bn.h>
// #include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdlib.h>
#if !defined(OPENSSL_SYS_MACOSX)
#include <malloc.h>
#endif
#include "ax_api.h"
#include "ax_embSeEngine_Internal.h"
#include "fsl_sscp_a71ch.h"
#include "sm_printf.h"
#include "nxLog_App.h"
#include "nxEnsure.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
#ifdef OPENSSL_NO_DYNAMIC_ENGINE
#undef OPENSSL_NO_DYNAMIC_ENGINE
#endif
#endif

// <Conditionally activate features at compile time>
#define PRIVATE_KEY_HANDOVER_TO_SW
#define PUBLIC_KEY_HANDOVER_TO_SW
// </Conditionally activate features at compile time>

/* Define ECDH secret key size */
#define ECDH_MAX_LEN        32

#define EMBSE_MAX_ECC_PUBKEY_BUF   (2*96 + 1)  // Corresponds to 768 bit ECC key

/* Maximum Key Index supported by the A70CM SE */
#define EMBSE_A70CM_MAX_PUBLIC_KEY_INDEX 2

/* Logging related defines */
#define EMBSE_MAX_PRINT_BUF_SIZE    (511)

#define LOG_FLOW_MASK 0x01
#define LOG_DBG_MASK  0x02
#define LOG_ERR_MASK  0x04

#define LOG_FLOW_ON 0x01
#define LOG_DBG_ON  0x02
#define LOG_ERR_ON  0x04

// Adjust to the required default log level.
static int EMBSE_LogControl = (LOG_ERR_ON | LOG_DBG_ON | LOG_FLOW_ON);  // Full log
// static int EMBSE_LogControl = (LOG_ERR_ON);  // Only Errors

static axKeyIdentifier_t eccSigningKeys[] = {
    {A71CH_SSI_KEY_PAIR, A71CH_KEY_PAIR_0},
    {A71CH_SSI_KEY_PAIR, A71CH_KEY_PAIR_1},
    {A71CH_SSI_KEY_PAIR, A71CH_KEY_PAIR_2},
    {A71CH_SSI_KEY_PAIR, A71CH_KEY_PAIR_3}
};

static axKeyIdentifier_t eccVerifyKeys[] = {
    {A71CH_SSI_PUBLIC_KEY, A71CH_PUBLIC_KEY_0},
    {A71CH_SSI_PUBLIC_KEY, A71CH_PUBLIC_KEY_1},
    {A71CH_SSI_PUBLIC_KEY, A71CH_PUBLIC_KEY_2}
};

static axKeyIdentifier_t eccDhStaticKeys[] = {
    {A71CH_SSI_KEY_PAIR, A71CH_KEY_PAIR_0},
    {A71CH_SSI_KEY_PAIR, A71CH_KEY_PAIR_1},
    {A71CH_SSI_KEY_PAIR, A71CH_KEY_PAIR_2},
    {A71CH_SSI_KEY_PAIR, A71CH_KEY_PAIR_3}
};

// Locally used utility functions
static U16 getEcKeyReference(const EC_KEY *eckey, axKeyIdentifier_t *validKeys, int nKeys,
                             SST_Identifier_t *ident, SST_Index_t *idx);
static U16 axAdaptSize(U8* pOut, U16 expectedLen, const U8 *pIn, U16 actualLen);
static void EmbSe_Print(int flag, const char * format, ...);
static void EmbSe_PrintPayload(int flag, const U8 *pPayload, U16 nLength, const char *title);
static U16 EmbSe_A70Init(void);

/* engine name */
static const char *embSe_id = OPENSSL_ENGINE_EMBSE_ID;
static const char *embSe_name = "se hardware engine support";

/* Random Num Status, used when Get Rand Status is invoked */
unsigned short gRandStatus = 1;

const int Version1 = 1;  //-> Release Version1.Version2.Version3
const int Version2 = 0;
const int Version3 = 1;

/* ecdsa_method struct definition from */
struct ecdsa_method
{
    const char *name;
    ECDSA_SIG *(*ecdsa_do_sign)(const unsigned char *dgst, int dgst_len,
            const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey);
    int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
            BIGNUM **r);
    int (*ecdsa_do_verify)(const unsigned char *dgst, int dgst_len,
            const ECDSA_SIG *sig, EC_KEY *eckey);
#if 0
    int (*init)(EC_KEY *eckey);
    int (*finish)(EC_KEY *eckey);
#endif
    int flags;
    char *app_data;
};

/* ecdh_method struct definition from ech_locl.h*/
struct ecdh_method
{
    const char *name;
    int (*compute_key)(void *key, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
#if 0
    int (*init)(EC_KEY *eckey);
    int (*finish)(EC_KEY *eckey);
#endif
    int flags;
    char *app_data;
};

/* Engine API Declaration */
static int EmbSe_Rand(unsigned char *buf, int num);
static int EmbSe_Rand_Status(void);

static ECDSA_SIG *EmbSe_ECDSA_Do_Sign(const unsigned char *dgst, int dgst_len,
        const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey);
static int EmbSe_ECDSA_Sign_Setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
        BIGNUM **r);
static int EmbSe_ECDSA_Do_Verify(const unsigned char *dgst, int dgst_len,
        const ECDSA_SIG *sig, EC_KEY *eckey);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static int EmbSe_Compute_Key(void *sh_secret,
    size_t sec_len,
    const EC_POINT *pub_key,
    EC_KEY *ecdh,
    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
#else
static int EmbSe_Simple_Compute_Key(unsigned char **pout,
    size_t *poutlen,
    const EC_POINT *pub_key,
    const EC_KEY *ecdh);
static int EmbSe_Simple_Key_gen(EC_KEY *key);
#endif

/* Fill in implemented Engine methods in respective data structures */
static RAND_METHOD EmbSe_RAND =
{
    NULL,               /* RAND_seed() */
    EmbSe_Rand,         /* RAND_bytes() */
    NULL,               /* RAND_cleanup() */
    NULL,               /* RAND_add() */
    EmbSe_Rand,         /* RAND_pseudo_rand() */
    EmbSe_Rand_Status   /* RAND_status() */
};

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
static ECDSA_METHOD EmbSe_ECDSA = {
    "e2se_ecdsa",
    *EmbSe_ECDSA_Do_Sign,
    EmbSe_ECDSA_Sign_Setup,
    EmbSe_ECDSA_Do_Verify,
    0,
    NULL
};

static ECDH_METHOD EmbSe_ECDH = {
    "e2se_ecdh",
    *EmbSe_Compute_Key,
    0,
    NULL
};
#else
// Renamed 'ossl_ecdsa_sign' from openssl-1.1.0j/crypto/ec/ecdsa_ossl.c
static int my_ossl_ecdsa_sign(int type, const unsigned char *dgst, int dlen,
                    unsigned char *sig, unsigned int *siglen,
                    const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    int rv = 0;

    ENSURE_OR_GO_EXIT(siglen != NULL);
    RAND_seed(dgst, dlen);
    s = ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey);
    if (s == NULL) {
        *siglen = 0;
        return 0;
    }
    *siglen = i2d_ECDSA_SIG(s, &sig);
    ECDSA_SIG_free(s);
    rv = 1;
exit:
    return rv;
}

// Renamed 'ossl_ecdsa_verify' from openssl-1.1.0j/crypto/ec/ecdsa_ossl.c
static int my_ossl_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                      const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    ECDSA_SIG *s;
    const unsigned char *p = sigbuf;
    unsigned char *der = NULL;
    int derlen = -1;
    int ret = -1;

    s = ECDSA_SIG_new();
    if (s == NULL)
        return (ret);
    if (d2i_ECDSA_SIG(&s, &p, sig_len) == NULL)
        goto err;
    /* Ensure signature uses DER and doesn't have trailing garbage */
    derlen = i2d_ECDSA_SIG(s, &der);
    if (derlen != sig_len || memcmp(sigbuf, der, derlen) != 0)
        goto err;
    ret = ECDSA_do_verify(dgst, dgst_len, s, eckey);
 err:
    OPENSSL_clear_free(der, derlen);
    ECDSA_SIG_free(s);
    return (ret);
}

static EC_KEY_METHOD *EmbSe_EC = NULL;
static EC_KEY_METHOD *EmbSe_EC_Default = NULL;
static int setup_ec_key_method(void) {
    EmbSe_EC_Default = (EC_KEY_METHOD *)EC_KEY_get_default_method();
    EmbSe_EC = EC_KEY_METHOD_new(NULL);
    if (EmbSe_EC == NULL) {
        return 0;
    }
    // NOTE: Equivalent of set_name does not exist for OpenSSL 1.1
    // EC_KEY_METHOD_set_name(EmbSe_EC, "e2se_ecdsa");
    EC_KEY_METHOD_set_sign(EmbSe_EC, my_ossl_ecdsa_sign, EmbSe_ECDSA_Sign_Setup, EmbSe_ECDSA_Do_Sign);
    EC_KEY_METHOD_set_verify(EmbSe_EC, my_ossl_ecdsa_verify, EmbSe_ECDSA_Do_Verify);
    EC_KEY_METHOD_set_compute_key(EmbSe_EC, EmbSe_Simple_Compute_Key);
    EC_KEY_METHOD_set_keygen(EmbSe_EC, EmbSe_Simple_Key_gen);
    return 1;
}
#endif // (OPENSSL_VERSION_NUMBER < 0x10100000L)

#ifndef OPENSSL_NO_HW

/* The definitions for control commands specific to this engine */
#define EMBSE_LOG_LEVEL   ENGINE_CMD_BASE
#define EMBSE_CMD_SO_PATH (ENGINE_CMD_BASE + 1)

static const ENGINE_CMD_DEFN embSe_cmd_defns[] = {
    {EMBSE_LOG_LEVEL,
        "LOG_LEVEL",
        "Specifies the Log level (Error=0x04; Debug=0x02; Flow=0x01; Or'd combinations possible)",
        ENGINE_CMD_FLAG_NUMERIC},
    {EMBSE_CMD_SO_PATH,
        "SO_PATH",
        "Specifies the path to the 'e2se ssl' shared library (not implemented)",
        ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

/* Engine API's for initialization and cleanup */
static int EmbSe_Destroy(ENGINE *e)
{
    AX_UNUSED_ARG(e);
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Destroy(): Entry\n");
    return 1;
}


/****** ENGINE API's *******/
static int EmbSe_Init(ENGINE *e)
{
    U16 sw = 0;

    AX_UNUSED_ARG(e);
    /* Initialize the Engine Mutex */
    CryptoIpc_MutexInit(AX_CI_TRUE);
    sw = EmbSe_A70Init();
    if (sw != SW_OK)
    {
        EmbSe_Print(LOG_ERR_ON, "Call to EmbSe_A70Init() failed with return code 0x%04X\n", sw);
        return -1;
    }
    EmbSe_Print(LOG_FLOW_ON, "Version: %d.%d.%d\n", Version1, Version2, Version3);
#ifdef __gnu_linux__
    mallopt(M_MMAP_THRESHOLD, 125);
#endif
    /* Engine is ready to use */
    return 1;
}

static int EmbSe_Finish(ENGINE *e)
{
    AX_UNUSED_ARG(e);
    SM_Close(NULL, SMCOM_CLOSE_MODE_STD);
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Finish(): Entry\n");
    return 1;
}

static int EmbSe_Ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    AX_UNUSED_ARG(e);
    /* Values of String Variables are received in p, while values of Numeric ones are in i */
    switch(cmd)
    {
        case EMBSE_LOG_LEVEL:
            EmbSe_Print(LOG_FLOW_ON, "Control Command EMBSE_LOG_LEVEL; requested log level = %ld\n", i);
            if (i < 0x08)
            {
                EMBSE_LogControl = i & 0x07;
            }
            else
            {
                EmbSe_Print(LOG_DBG_ON, "Invalid Control Command value for EMBSE_LOG_LEVEL\n");
            }
            return 1;
        case EMBSE_CMD_SO_PATH:
            EmbSe_Print(LOG_ERR_ON, "Control command EMBSE_CMD_SO_PATH has not been implemented.\n");
            return 0;
        default:
            break;
    }
    return 0;
}

/* This internal function is used by ENGINE_e2se() and possibly by the
 * "dynamic" ENGINE support too */
static int bind_helper(ENGINE *e)
{
    if (!ENGINE_set_id(e, embSe_id) ||
            !ENGINE_set_name(e, embSe_name) ||
            !ENGINE_set_destroy_function(e, &EmbSe_Destroy) ||
            !ENGINE_set_init_function(e, &EmbSe_Init) ||
            !ENGINE_set_finish_function(e, &EmbSe_Finish) ||
            !ENGINE_set_ctrl_function(e, &EmbSe_Ctrl) ||
            !ENGINE_set_cmd_defns(e, &embSe_cmd_defns[0]) ||
            !ENGINE_set_RAND(e, &EmbSe_RAND) ||
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
            !ENGINE_set_ECDSA(e, &EmbSe_ECDSA) ||
            !ENGINE_set_ECDH(e, &EmbSe_ECDH))
#else
        !setup_ec_key_method() ||
        !ENGINE_set_EC(e, EmbSe_EC))
#endif
    {
        return 0;
    }

    return 1;
}

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *EngineEmbSe(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
    {
        return NULL;
    }
    if (!bind_helper(ret))
    {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void EngineEmbSe_Load(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = EngineEmbSe();
    if (!toadd) return;
    ENGINE_add(toadd);
    ENGINE_free(toadd);
    ERR_clear_error();
    EmbSe_Print(LOG_FLOW_ON, "EngineEmbSe_Load succeeded!\n");
}
#else
/* This stuff is needed if this ENGINE is being compiled into a self-contained
 * shared-library. */
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, embSe_id) != 0))
        return 0;
    if (!bind_helper(e))
        return 0;
    return 1;
}
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
#endif /* OPENSSL_NO_DYNAMIC_ENGINE */
#endif /* !OPENSSL_NO_HW */


#define MAX_RND_CHUNK A71CH_SCP03_MAX_PAYLOAD_SIZE
 /**
 * Implementation of Engine API for Random Number Generation. Invokes Host API RND_GetRandom
 * @param[in,out] buf   buffer to store the generated Random Number
 * @param[in]     num   number of random bytes requested
 * @retval  0 upon failure
 * @retval  1 upon success
 */
static int EmbSe_Rand(unsigned char *buf, int num)
{
    U16 sw = ERR_GENERAL_ERROR;
    int requested = 0;
    int offset = 0;
    int chunk = 0;
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Rand invoked requesting %d random bytes\n", num);
    memset(buf,0,num);
    CryptoIpc_MutexLock();
    requested = num;
    while (requested > 0)
    {
        if (requested > MAX_RND_CHUNK)
        {
            chunk = MAX_RND_CHUNK;
        }
        else
        {
            chunk = requested;
        }
        sw = A71_GetRandom (buf+offset, chunk);
        if (sw != SW_OK) {
            break;
        }
        offset += chunk;
        requested -= chunk;
    }
    CryptoIpc_MutexUnlock();
    gRandStatus = sw;

    if (sw == SW_OK)
    {
        return 1;
    }
    else
    {
        EmbSe_Print(LOG_ERR_ON, "Call to RND_GetRandom failed with 0x%04X\n", sw);
        return 0;
    }
}

/**
* @function EmbSe_Rand_Status
* @description Engine API to return the status from invocation of RND_GetRandom()
* @param void
* @return value U16 of previous RND_GetRandom() API.
*/
static int EmbSe_Rand_Status(void)
{
     EmbSe_Print(LOG_FLOW_ON, "EmbSe_Rand_Status invoked\n");
     return (int)gRandStatus;
}


// EmbSe RSA API's
/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH  36


// EmbSE ECDSA Implementation
// --------------------------
static ECDSA_SIG *EmbSe_ECDSA_Do_Sign(const unsigned char *dgst, int dgst_len,
        const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey)
{
    U8 sigDER[256];
    U16 sigDERLen = sizeof(sigDER);
    U16 sw;
    ECDSA_SIG *pSig;
    EC_KEY *dup_eckey = NULL;
    U8 *pp;
    SST_Identifier_t ident;
    SST_Index_t idx;
    U8 dgstBuf[32];
    U16 dgstBufLen = sizeof(dgstBuf);

    sw = getEcKeyReference(eckey, eccSigningKeys, sizeof(eccSigningKeys)/sizeof(axKeyIdentifier_t),
        &ident, &idx);
    if (sw == SW_OK)
    {
        EmbSe_Print(LOG_FLOW_ON, "ECC_Sign(ident=%d, idx=%d; dgstLen=%d)\n", ident, idx, dgst_len);
        axAdaptSize(dgstBuf, dgstBufLen, dgst, dgst_len);
        CryptoIpc_MutexLock();
        sw = A71_EccSign(idx, (const U8*)dgstBuf, dgstBufLen, (U8*)sigDER, (U16*)&sigDERLen);
        CryptoIpc_MutexUnlock();
        if (sw != SW_OK)
        {
            EmbSe_Print(LOG_ERR_ON, "SE signature creation error: 0x%04X.\n", sw);
            return NULL;
        }
        EmbSe_Print(LOG_FLOW_ON, "A71_EccSign called successfully: sigDERLen=%d\n", sigDERLen);

        /* sig is DER encoded. Transform to ECDSA_SIG and return this */
        pp = (U8*)sigDER;
        pSig = ECDSA_SIG_new();

        if (pSig == NULL)
        {
            EmbSe_Print(LOG_ERR_ON, "ECDSA_SIG_new call failed\n");
            return NULL;
        }

        if (d2i_ECDSA_SIG((ECDSA_SIG**)&pSig, (const unsigned char**)&pp, sigDERLen)  == NULL)
        {
            EmbSe_Print(LOG_ERR_ON, "d2i_ECDSA_SIG failed\n");
            return NULL;
        }
        EmbSe_Print(LOG_FLOW_ON, "EmbSe_ECDSA_Do_Sign success.\n");
        return pSig;
    }
    else if (sw == ERR_IDENT_IDX_RANGE)
    {
        EmbSe_Print(LOG_ERR_ON, "Reference Key with identifier or index out of range: 0x%04X.\n", sw);
        return NULL;
    }
    else if (sw == ERR_NO_PRIVATE_KEY)
    {
        EmbSe_Print(LOG_ERR_ON, "Expecting private key (by value or reference): 0x%04X.\n", sw);
        return NULL;
    }
    else if (sw == ERR_PATTERN_COMPARE_FAILED)
    {
#ifdef PRIVATE_KEY_HANDOVER_TO_SW
        // Invoke OpenSSL sign API if no valid key reference is detected
        EmbSe_Print(LOG_FLOW_ON,"No matching key in A71CH. Invoking OpenSSL API: ECDSA_do_sign_ex.\n");
        /* Create a duplicate key */
        dup_eckey = EC_KEY_dup(eckey);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        /* Attach OpenSSL's SW method to duplicate key */
        if (!ECDSA_set_method(dup_eckey, ECDSA_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL ECDSA_set_method failure..\n");
            return NULL;
        }
#else
        /* Attach OpenSSL's SW method to duplicate key */
        if (!EC_KEY_set_method(dup_eckey, EC_KEY_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL EC_KEY_set_method failure..\n");
            return NULL;
        }
#endif
        /* Invoke OpenSSL's sign API and return result */
        return ECDSA_do_sign_ex(dgst, dgst_len, inv, rp, dup_eckey);
#else
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Sign expected a reference key: 0x%04X.\n", sw);
        return NULL;
#endif
    }
    else
    {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Sign unexpected key type: 0x%04X.\n", sw);
        return NULL;
    }
}

static int EmbSe_ECDSA_Sign_Setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
        BIGNUM **r)
{
    return 1;
}

static int EmbSe_ECDSA_Do_Verify(const unsigned char *dgst, int dgst_len,
        const ECDSA_SIG *sig, EC_KEY *eckey)
{
    U16 sw;
    U8 retval = 0;
    int nRet = 0;
    int i;
    int flagHandleKey = AX_ENGINE_INVOKE_NOTHING;
    EC_KEY *dup_eckey = NULL;
    U8 *pSignatureDER, *pSigTmp;
    U16 sigLen;
    SST_Identifier_t ident;
    SST_Index_t idx;
    size_t pub_key_len;
    const EC_POINT *pub_key_point;
    U8 refPub[EMBSE_MAX_ECC_PUBKEY_BUF];

    EmbSe_Print(LOG_FLOW_ON, "Invoking EmbSe_ECDSA_Do_Verify(..)\n");

    if (!eckey)
    {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: No EC Key provided as input.\n");
        return -1;
    }
    if (!sig)
    {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: No signature provided as input.\n");
        return -1;
    }

    /* Convert ECDSA_SIG to DER and print */
    sigLen = i2d_ECDSA_SIG((ECDSA_SIG*)sig, NULL);
    if (sigLen != 0)
    {
        pSignatureDER = (U8*)OPENSSL_malloc(sigLen);
        pSigTmp = pSignatureDER;
        // The pointer passed as second argument will point past the end of the returned signature
        // upon return. Which explains pointer copy operation before the call.
        i2d_ECDSA_SIG((ECDSA_SIG*)sig, &pSigTmp);
    }
    else
    {
        EmbSe_Print(LOG_ERR_ON, "Call to i2d_ECDSA_SIG failed\n");
        return -1;
    }
    EmbSe_Print(LOG_DBG_ON, "====>SIGNATURE (len=%d)\n", sigLen);
    EmbSe_PrintPayload(LOG_DBG_ON, pSignatureDER, sigLen, "");
    EmbSe_PrintPayload(LOG_DBG_ON, dgst, dgst_len, "====>DIGEST");

    sw = getEcKeyReference(eckey, eccVerifyKeys, sizeof(eccVerifyKeys)/sizeof(axKeyIdentifier_t),
        &ident, &idx);
    if (sw == SW_OK)
    {
        flagHandleKey = AX_ENGINE_INVOKE_SE;
    }
    else if ( (sw == ERR_NO_PRIVATE_KEY) || (sw == ERR_PATTERN_COMPARE_FAILED) )
    {
        // Check whether the public key passed by value matches one of
        // the provisioned public keys.

        /* Extract public key */
        pub_key_point = EC_KEY_get0_public_key(eckey);
        if (!pub_key_point)
        {
            EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: EC Key public key error.\n");
            nRet = -1;
            goto clean_mem_up;
        }
        pub_key_len = EC_POINT_point2oct(EC_KEY_get0_group(eckey), pub_key_point,
                POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
        if ( (pub_key_len == 0) || (pub_key_len > sizeof(refPub)) )
        {
            EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: Preparation to convert public key into byte array failed.\n");
            nRet = -1;
            goto clean_mem_up;
        }
        if ( EC_POINT_point2oct(EC_KEY_get0_group(eckey), pub_key_point,
                POINT_CONVERSION_UNCOMPRESSED, refPub, pub_key_len, NULL) == 0 )
        {
            EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: Pub key data extraction error.\n");
            nRet = -1;
            goto clean_mem_up;
        }

        EmbSe_PrintPayload(LOG_DBG_ON, refPub, (U16)pub_key_len, "PubKey (Verify)");

        flagHandleKey = AX_ENGINE_INVOKE_OPENSSL_SW;
        // The local data structure eccVerifyKeys must match the storage
        // capability of the attached secure element.
        // Failure to retrieve a key from the secure element will not be
        // considered fatal (the value may not have been provisioned)
        CryptoIpc_MutexLock();
        for (i=0; i<(int)(sizeof(eccVerifyKeys)/sizeof(axKeyIdentifier_t)); i++)
        {
            U8 fetchedPubKey[65];
            U16 fetchedPubKeyLen = sizeof(fetchedPubKey);

            memset(fetchedPubKey, 0, fetchedPubKeyLen);
            idx = eccVerifyKeys[i].idx;

            EmbSe_Print(LOG_DBG_ON, "A71_GetEccPublicKey(0x%02X)\n", (SST_Index_t)idx);
            sw = A71_GetEccPublicKey((SST_Index_t)idx, fetchedPubKey, &fetchedPubKeyLen);
            if (sw == SW_OK)
            {
                if (memcmp(refPub, fetchedPubKey, sizeof(fetchedPubKey)) == 0)
                {
                    // We have a match.
                    flagHandleKey = AX_ENGINE_INVOKE_SE;
                    EmbSe_Print(LOG_FLOW_ON, "EmbSe_ECDSA_Do_Verify: Found matching public key at index 0x%02X\n", idx);
                    break;
                }
            }
        }
        CryptoIpc_MutexUnlock();
    }
    else
    {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: No matching/valid public key\n");
        nRet = -1;
        goto clean_mem_up;
    }

    if (flagHandleKey == AX_ENGINE_INVOKE_SE)
    {
        U8 dgstBuf[32];
        U16 dgstBufLen = sizeof(dgstBuf);

        EmbSe_Print(LOG_FLOW_ON, "ECC_Verify(KeyIdent=%d, KeyIndex=%d, dgst_len=%d, sigLen=%d)\n",
          ident, idx, dgst_len, sigLen);
        axAdaptSize(dgstBuf, dgstBufLen, dgst, dgst_len);
        CryptoIpc_MutexLock();
        sw = A71_EccVerify(idx, dgstBuf, dgstBufLen, pSignatureDER, sigLen, (U8*)&retval);
        CryptoIpc_MutexUnlock();
        if (sw != SW_OK)
        {
            EmbSe_Print(LOG_ERR_ON, "A71_EccVerify returned with Error: 0x%04X\n", sw);
            nRet = -1;
            goto clean_mem_up;
        }
        else
        {
            if (retval == 1)
                EmbSe_Print(LOG_FLOW_ON, "Verification PASS\n");
            else
                EmbSe_Print(LOG_FLOW_ON, "Verification FAIL\n");
        }
        nRet = (int)retval;
    }
    else if (flagHandleKey == AX_ENGINE_INVOKE_OPENSSL_SW)
    {
#ifdef PUBLIC_KEY_HANDOVER_TO_SW
        EmbSe_Print(LOG_FLOW_ON, "No matching key in A71CH. Invoking OpenSSL API: ECDSA_do_verify.\n");
        /* Create a duplicate key */
        dup_eckey = EC_KEY_dup(eckey);
        if (dup_eckey == NULL)
        {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL verify: Failed to duplicate key.\n");
            nRet = -1;
            goto clean_mem_up;
        }
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        /* Attach OpenSSL's SW methods to duplicate key */
        if (!ECDSA_set_method(dup_eckey, ECDSA_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL ECDSA_set_method failure..\n");
            nRet = -1;
            EC_KEY_free(dup_eckey);
            goto clean_mem_up;
        }
#else
        /* Attach OpenSSL's SW methods to duplicate key */
        if (!EC_KEY_set_method(dup_eckey, EC_KEY_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL EC_KEY_set_method failure..\n");
            nRet = -1;
            EC_KEY_free(dup_eckey);
            goto clean_mem_up;
        }
#endif
        /* Invoke OpenSSL verify and return result */
        nRet = ECDSA_do_verify(dgst, dgst_len, sig, dup_eckey);
        if (nRet == 1)
        {
            EmbSe_Print(LOG_FLOW_ON, "Verification by OpenSSL PASS\n");
        }
        else
        {
            EmbSe_Print(LOG_FLOW_ON, "Verification by OpenSSL FAIL (nRet=%d)\n", nRet);
        }
        EC_KEY_free(dup_eckey);
#else
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify expected a reference key or a matching stored public key.\n");
        nRet = -1;
        goto clean_mem_up;
#endif
    }
    else
    {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_ECDSA_Do_Verify: unexpected conditional branch (flagHandleKey=%d).\n", flagHandleKey);
        nRet = -1;
        goto clean_mem_up;
    }

clean_mem_up:
    OPENSSL_free(pSignatureDER);

    return nRet;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
/**
 * Engine API implementation for computing shared secret, based on local private key, remote public key and an
 * optional  KDF(Key Derivation Function).
 *
 * @param[out] sh_secret buffer that will contain the computed shared secret (raw value if KDF is NULL).
 * @param[in]  sec_len   length of computed shared secret.
 * @param[in]  pub_key   public key of remote entity.
 * @param[in]  ecdh      reference to private key object of local entity.
 * @param[in] (*KDF)     reference to a function that implements Key Derivation Function (hash on raw secret)
 *
 * @param: (*KDF)in- Reference to buffer containing the generated shared secret.
 * @param: (*KDF)inlen- Length of the input
 * @param: (*KDF)out - Buffer that returns final output on running KDF
 * @param: (*KDF)outlen - returns length of computed output on running KDF
 * @return: On failure, returns -1; On success returns length of computed secret.
 */
static int EmbSe_Compute_Key(void *sh_secret,
    size_t sec_len,
    const EC_POINT *pub_key,
    EC_KEY *ecdh,
    void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen))
#else
static int EmbSe_Simple_Compute_Key(unsigned char **pout,
    size_t *poutlen,
    const EC_POINT *pub_key,
    const EC_KEY *ecdh)
#endif
{
    U16 sw;
    U16 field_size_bits = 0;
    const EC_GROUP *key_group = NULL;
    U8 *pubKeyBuf = NULL;
    U16 pubKeyBufLen = 0;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    int ret = -1;
#else
    int ret = 0;
#endif
    U8 *shSecBuf = NULL;
    U16 shSecBufLen = 0;
    SST_Identifier_t ident;
    SST_Index_t idx;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Compute_Key invoked (ecdh)\n");
    /* Requested secret length limit check */
    if (sec_len > ECDH_MAX_LEN) {
        EmbSe_Print(LOG_ERR_ON, "Requested secret too long. Try <= %d.\n", ECDH_MAX_LEN);
        return ret;
    }
#else
    EmbSe_Print(LOG_FLOW_ON, "EmbSe_Simple_Compute_Key invoked (ecdh)\n");
#endif
    /* Get the key group */
    key_group = EC_KEY_get0_group(ecdh);
    if (!key_group)
    {
        EmbSe_Print(LOG_ERR_ON, "Unable to extract ECDH key group.\n");
        goto err;
    }
    else
    {/* Calculate length of field element for the key group */
        field_size_bits = (U16)EC_GROUP_get_degree(key_group);
        if (!field_size_bits)
        {
            EmbSe_Print(LOG_ERR_ON, "Unable to extract ECDH key field length.\n");
            goto err;
        }
    }

    /* Extract Public Key Data  */
    /****************************/
    // Check if pub key is on the curve group
    if (!EC_POINT_is_on_curve(key_group, pub_key, NULL))
    {
        EmbSe_Print(LOG_ERR_ON, "ECDH Public key error(incompatible group).\n");
        goto err;
    }
    // Get the size of public key -> pass NULL for buffer
    pubKeyBufLen = (U16) EC_POINT_point2oct(key_group, pub_key, POINT_CONVERSION_UNCOMPRESSED,
                        NULL, pubKeyBufLen, NULL);
    // Allocate memory for public key data & check allocation
    pubKeyBuf = malloc(pubKeyBufLen * sizeof(U8));
    if (!pubKeyBuf)
    {
        EmbSe_Print(LOG_ERR_ON, "malloc failure for ECDH public key data.\n");
        goto err;
    }
    // Get public key data
    if (!EC_POINT_point2oct(key_group, pub_key, POINT_CONVERSION_UNCOMPRESSED, pubKeyBuf, pubKeyBufLen, NULL))
    {
        EmbSe_Print(LOG_ERR_ON, "ECDH public key data error (EC_POINT_point2oct).\n");
        goto err;
    }

    /* Secure Element Call (if applicable) */
    /***************************************/
    shSecBufLen = (U16)(field_size_bits+7)/8;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    shSecBuf = malloc(shSecBufLen * sizeof(U8));
#else
    shSecBuf = OPENSSL_malloc(shSecBufLen * sizeof(U8));
#endif

    sw = getEcKeyReference(ecdh, eccDhStaticKeys, sizeof(eccDhStaticKeys)/sizeof(axKeyIdentifier_t),
        &ident, &idx);
    if (sw == SW_OK)
    {
        EmbSe_Print(LOG_FLOW_ON, "A71_EcdhGetSharedSecret(idx=%d, pubKeyLen=%d, shSecBufLen=%d)\n",
            idx, pubKeyBufLen, shSecBufLen);
        CryptoIpc_MutexLock();
        sw = A71_EcdhGetSharedSecret(idx, pubKeyBuf, pubKeyBufLen, shSecBuf, &shSecBufLen);
        CryptoIpc_MutexUnlock();
        if (sw == SW_OK)
        {
            EmbSe_Print(LOG_FLOW_ON, "A71CH: A71_EcdhGetSharedSecret OK: Status code 0x%04x\n", sw);
        }
        else
        {
            EmbSe_Print(LOG_ERR_ON, "A71CH: A71_EcdhGetSharedSecret Error: Status code 0x%04x\n", sw);
            goto err;
        }
    }
    else if (sw == ERR_IDENT_IDX_RANGE)
    {
        EmbSe_Print(LOG_ERR_ON, "Reference Key with identifier or index out of range: 0x%04X.\n", sw);
        goto err;
    }
    else if (sw == ERR_NO_PRIVATE_KEY)
    {
        EmbSe_Print(LOG_ERR_ON, "Expecting private key (by value or reference): 0x%04X.\n", sw);
        goto err;
    }
    else if (sw == ERR_PATTERN_COMPARE_FAILED)
    {
#ifdef PRIVATE_KEY_HANDOVER_TO_SW
        EC_KEY *dup_ecdh = NULL;
        int ecdh_ret = -1;

        // Delegate to OpenSSL SW implementation
        EmbSe_Print(LOG_FLOW_ON,"No matching key in A71CH. Invoking OpenSSL API: ECDH_compute_key.\n");
        /* Create a duplicate key */
        dup_ecdh = EC_KEY_dup(ecdh);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
        /* Attach OpenSSL's SW method to duplicate key */
        if (!ECDH_set_method(dup_ecdh, ECDH_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL ECDH_set_method failure.\n");
            goto err;
        }
#else
        /* Attach OpenSSL's SW method to duplicate key */
        if (!EC_KEY_set_method(dup_ecdh, EC_KEY_OpenSSL())) {
            EmbSe_Print(LOG_ERR_ON, "OpenSSL EC_KEY_set_method failure..\n");
            goto err;
        }
#endif
        /* Invoke OpenSSL ECDH_compute_key and return result */
        // int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key, EC_KEY *ecdh,
        // void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen));
        ecdh_ret = ECDH_compute_key(shSecBuf, shSecBufLen, pub_key, dup_ecdh, NULL);
        EC_KEY_free(dup_ecdh);
        if (0 < ecdh_ret)
        {
            EmbSe_Print(LOG_FLOW_ON, "ECDH_compute_key by OpenSSL PASS\n");
            shSecBufLen = (U16)ecdh_ret;
        }
        else
        {
            EmbSe_Print(LOG_ERR_ON, "ECDH_compute_key by OpenSSL FAILS with %d.\n", ecdh_ret);
            goto err;
        }
#else
        EmbSe_Print(LOG_ERR_ON, "EmbSe_Compute_Key expected a reference key: 0x%04X.\n", sw);
        goto err;
#endif
    }
    else
    {
        EmbSe_Print(LOG_ERR_ON, "EmbSe_Compute_Key unexpected key type: 0x%04X.\n", sw);
        goto err;
    }

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    /* Finally run the KDF, if provided */
    memset(sh_secret, 0, shSecBufLen);
    if (KDF != 0)
    {
        if (KDF(shSecBuf, shSecBufLen, sh_secret, &sec_len) == NULL)
        {
            EmbSe_Print(LOG_ERR_ON, "KDF failed.\n");
            goto err;
        }
        ret = (int)sec_len;
    }
    else
    {
        /* When KDF=NULL, return raw secret, copy asked length */
        if (sec_len > shSecBufLen)
        {
            sec_len = shSecBufLen;
        }
        memcpy(sh_secret, shSecBuf, sec_len);
        ret = (int)sec_len;
    }
#else
    *pout = shSecBuf;
    *poutlen = shSecBufLen;
    ret = 1;
#endif

    // Never print shared secret
    // EmbSe_PrintPayload(LOG_DBG_ON, sh_secret, sec_len, "Shared Secret: ");

err:
    /* Free all allocated memory */
    if (pubKeyBuf)
        free(pubKeyBuf);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    if (shSecBuf)
        free(shSecBuf);
#endif
    return ret;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#else
static int EmbSe_Simple_Key_gen(EC_KEY *key)
{
    int(*openssl_Key_gen_sw)(EC_KEY * key) = NULL;
    EC_KEY_METHOD_get_keygen((EC_KEY_METHOD *)EmbSe_EC_Default, &openssl_Key_gen_sw);
    return openssl_Key_gen_sw(key);
}
#endif

/*  Support functions */
/**********************/

/**
 * Initialize communication with Secure Element.
 * Supporting function for Engine Init.
 *
 * @retval ::SW_OK Upon successful execution
 */
static U16 EmbSe_A70Init(void)
{
    U16 connectStatus = 0;
    U8 Atr[64];
    U16 AtrLen = sizeof(Atr);
    SmCommState_t commState;
    sm_printf(DBGOUT, "Connect to A71CH. Chunksize at link layer = %d.\n", MAX_CHUNK_LENGTH_LINK);

#if defined(TDA8029_UART) || defined(SCI2C) || defined(PCSC)|| defined(T1oI2C)
    connectStatus = SM_Connect(NULL, &commState, Atr, &AtrLen);
#elif defined(SMCOM_JRCP_V1) || defined(SMCOM_JRCP_V2)
//  {
//      if (CONF_modules_load_file(NULL, "rjct_server",
//                            CONF_MFLAGS_IGNORE_MISSING_FILE) <= 0)
//      {
//          fprintf(stderr, "FATAL: error loading configuration file\n");
//          ERR_print_errors_fp(stderr);
//      }
//  }
    {
#ifdef SMCOM_JRCP_V2
        commState.connType = kType_SE_Conn_Type_JRCP_V2;
#endif
#ifdef SMCOM_JRCP_V1
        commState.connType = kType_SE_Conn_Type_JRCP_V1;
#endif
        char *rjctServerAddress = NULL;
        rjctServerAddress = getenv("RJCT_SERVER_ADDR");
        if (rjctServerAddress == NULL) {
            connectStatus = SM_RjctConnect(NULL, "127.0.0.1:8050", &commState, Atr, &AtrLen);
        }
        else {
            char szConnect[256];
            size_t connectLen = sizeof(szConnect);
            char szColonPort[] = ":8050";
            size_t colonPortLen = sizeof(szColonPort) + 1;
            if (sizeof(rjctServerAddress) > (connectLen-colonPortLen)) {
                sm_printf(DBGOUT, "Server address is too long: %s\n", rjctServerAddress);
                return ERR_NO_VALID_IP_PORT_PATTERN;
            }
            else {
                strcpy(szConnect, rjctServerAddress);
                //strcat(szConnect, szColonPort);
                sm_printf(DBGOUT, "Server address:port set to %s\n", szConnect);
                connectStatus = SM_RjctConnect(NULL, szConnect, &commState, Atr, &AtrLen);
            }
        }
    }
#else
    #error "No communication channel defined"
#endif // TDA8029
    if ( (connectStatus == ERR_CONNECT_LINK_FAILED) || (connectStatus == ERR_CONNECT_SELECT_FAILED) )
    {
        sm_printf(CONSOLE, "SM_Connect failed with status 0x%04X\n", connectStatus);
        return connectStatus;
    }
    else if ( connectStatus == SMCOM_COM_FAILED )
    {
        sm_printf(CONSOLE, "SM_Connect failed with status 0x%04X (Could not open communication channel)\n", connectStatus);
        return connectStatus;
    }
    else if ( connectStatus == SMCOM_PROTOCOL_FAILED)
    {
        sm_printf(CONSOLE, "SM_Connect failed with status 0x%04X (Could not establish communication protocol)\n", connectStatus);
        return connectStatus;
    }
    else if ( connectStatus == ERR_NO_VALID_IP_PORT_PATTERN )
    {
        sm_printf(DBGOUT, "Pass the IP address and port number as arguments, e.g. \"127.0.0.1:8050\"!\n");
        return connectStatus;
    }
    else
    {
        int i=0;
#if defined(SCI2C)
        sm_printf(CONSOLE, "SCI2C_"); // To highlight the ATR format for SCI2C deviates from ISO7816-3
#elif defined(SPI)
        sm_printf(CONSOLE, "SCSPI_");
#endif
        if (AtrLen > 0)
        {
            sm_printf(CONSOLE, "ATR=0x");
            for (i=0; i<AtrLen; i++) { sm_printf(CONSOLE, "%02X.", Atr[i]); }
            sm_printf(CONSOLE, "\n");
        }
#if defined(TDA8029_UART)
        sm_printf(CONSOLE, "UART Baudrate Idx: 0x%02X\n", commState.param2);
        sm_printf(CONSOLE, "T=1           TA1: 0x%02X\n", commState.param1);
#endif
        sm_printf(CONSOLE, "HostLib Version  : 0x%04X\n", commState.hostLibVersion);
        if (connectStatus != SW_OK)
        {
            sm_printf(CONSOLE, "Select failed. SW = 0x%04X\n", connectStatus);
            return connectStatus;
        }
        sm_printf(CONSOLE, "Applet Version   : 0x%04X\n", commState.appletVersion);
        sm_printf(CONSOLE, "SecureBox Version: 0x%04X\n", commState.sbVersion);
    }
    sm_printf(DBGOUT, "==========SELECT-DONE=========\n");
    return SW_OK;
}

void EmbSe_Print(int flag, const char * format, ...)
{
    unsigned char buffer[EMBSE_MAX_PRINT_BUF_SIZE + 1];
    int active = 0;
    va_list vArgs;

    if ( (flag & EMBSE_LogControl & LOG_FLOW_MASK) == LOG_FLOW_ON ) {
        active = 1;
        printf("e2a71ch-flw: ");
    }
    else if ( (flag & EMBSE_LogControl & LOG_DBG_MASK) == LOG_DBG_ON ) {
        active = 1;
        printf("e2a71ch-dbg: ");
    }
    else if ( (flag & EMBSE_LogControl & LOG_ERR_MASK) == LOG_ERR_ON ) {
        active = 1;
        printf("e2a71ch-err: ");
    }

    if (active == 1)
    {
        va_start(vArgs, format);
        vsnprintf((char *)buffer, EMBSE_MAX_PRINT_BUF_SIZE, (char const *)format, vArgs);
        va_end(vArgs);
        printf("%s", buffer);
    }
    return;
}

static void EmbSe_PrintPayload(int flag, const U8 *pPayload, U16 nLength, const char *title)
{
    U16 i;
    int active = 0;

    if ( (flag & EMBSE_LogControl & LOG_FLOW_MASK) == LOG_FLOW_ON ) {
        active = 1;
        printf("e2a71ch-flw: %s", title);
    }
    else if ( (flag & EMBSE_LogControl & LOG_DBG_MASK) == LOG_DBG_ON ) {
        active = 1;
        printf("e2a71ch-dbg: %s", title);
    }
    else if ( (flag & EMBSE_LogControl & LOG_ERR_MASK) == LOG_ERR_ON ) {
        active = 1;
        printf("e2a71ch-err: %s", title);
    }

    if (active == 1)
    {
        for (i = 0; i < nLength; i++)
        {
            if (i % 16 == 0) { printf("\n"); }
            printf("%02X ", pPayload[i]);
        }
        printf("\n");
    }
}

/**
 Return SW_OK when the ecKey passed as argument matches one of the valid
 keys contained in the validKeys array. Upon successfull execution ident
 and idx contain values that point to the appropriate key in the secure
 element.

 @return ERR_PATTERN_COMPARE_FAILED  Not a reference key
 @return ERR_IDENT_IDX_RANGE         Refers to unsupported key type (aka. identifier) or index
 @return ERR_NO_PRIVATE_KEY          No private key present
*/
static U16 getEcKeyReference(const EC_KEY *eckey, axKeyIdentifier_t *validKeys, int nKeys,
                             SST_Identifier_t *ident, SST_Index_t *idx)
{
    U16 sw = ERR_PATTERN_COMPARE_FAILED;
    const BIGNUM *prv_key_bn;
    U8 tmpBuf[EMBSE_MAX_ECC_PUBKEY_BUF];
    U16 privKeylen = 0;
    U8 Ident = 0;
    U8 Index = 0;
    U32 Coeff[2] = {0, 0};
    int i = 0;
    int j = 0;

    ENSURE_OR_GO_EXIT(ident != NULL);
    ENSURE_OR_GO_EXIT(idx != NULL);

    // printf("Debug: getEcKeyReference: Possible matches = %d\n", nKeys);

    /* Test for private key */
    prv_key_bn = EC_KEY_get0_private_key(eckey);
    if (prv_key_bn)
    {
        privKeylen = BN_bn2bin(prv_key_bn, tmpBuf);
        /* get Ident and Index */
        Ident = tmpBuf[privKeylen-2];
        Index = tmpBuf[privKeylen-1];
        /* Get double ID string */
        for (j=0; j<2; j++)
        {
            for (i=3;i<7;i++)
            {
                Coeff[j] |= tmpBuf[privKeylen-i-(j*4)]<< 8*(i-3);
            }
        }
        if ( ((unsigned int)Coeff[0] == (unsigned int)EMBSE_REFKEY_ID) &&
            ((unsigned int)Coeff[1] == (unsigned int)EMBSE_REFKEY_ID) )
        {
            sw = ERR_IDENT_IDX_RANGE;
            // Look for matching key
            for (i=0; i<nKeys; i++)
            {
                if ( (validKeys[i].ident == Ident) && (validKeys[i].idx == Index) )
                {
                    // We have a match
                    *ident = validKeys[i].ident;
                    *idx = validKeys[i].idx;
                    sw = SW_OK;
                    break;
                }
            }
        }
        else
        {
            sw = ERR_PATTERN_COMPARE_FAILED;
        }
    }
    else
    {
        sw = ERR_NO_PRIVATE_KEY;
    }

exit:
    return sw;
}

/**
 * Either zero sign extend \p pIn so it becomes \p expectedLen byte long
 * or truncate the right most byte.
 * The caller must ensure \p expectedLen is bigger than \p actualLen
 * @param[in,out]   pOut
 * @param[in]       expectedLen Zero sign extend/truncate until this length.
 * @param[in]       pIn  Array representation of big number, to be zero sign extended or truncated
 * @param[in]       actualLen Length of incoming array \p pIn
 *
 * @retval SW_OK In case of successfull execution
 * @retval ERR_API_ERROR Requested adjustment would result in truncation
 */
static U16 axAdaptSize(U8* pOut, U16 expectedLen, const U8 *pIn, U16 actualLen)
{
    U16 sw = SW_OK;

    int numExtraByte = (int)expectedLen - (int)actualLen;

    if (numExtraByte == 0) {
        memcpy(pOut, pIn, actualLen);
    }
    else if (numExtraByte < 0) {
        memcpy(pOut, pIn, expectedLen);
    }
    else {
        memcpy(pOut + numExtraByte, pIn, actualLen);
        memset(pOut, 0x00, numExtraByte);
    }

    return sw;
}
