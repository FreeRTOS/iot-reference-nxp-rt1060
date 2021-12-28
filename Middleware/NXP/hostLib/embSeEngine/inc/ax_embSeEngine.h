/*****************************************************************************
 * @section LICENSE
 * ----------------------------------------------------------------------------
 *
 * Copyright 2016 NXP
 * SPDX-License-Identifier: Apache-2.0
 * ----------------------------------------------------------------------------
 ******************************************************************************
 * OpenSSL Engine for Embedded Secure Element (A70CM)
 *
 * This engine invokes the API of axHostSw/a70cm that wraps APDU communication
 * with the A70CM secure element.
 *
 * The following operations are supported by this engine:
 * - Random number generation
 * - RSA signature generation
 * - RSA Encryption
 * - RSA Decryption
 * - RSA signature verification
 * - ECC sign
 * - ECC verify : reroute calls to openssl sw API when valid key is not detected
 * - ECDH compute_key (shared secret generation)
 * ----------------------------------------------------------------------------*/

#ifndef AX_EMB_SE_ENGINE_H
#define AX_EMB_SE_ENGINE_H

/* includes */
#include <openssl/ossl_typ.h>
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
//#include <openssl/dso.h>
#include <openssl/engine.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
#include <openssl/bn.h>
#ifdef __gnu_linux__
#include <sys/msg.h>
#include <sys/ipc.h>
#endif
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef TGT_A70CI
#define OPENSSL_ENGINE_EMBSE_ID "e2a70ci"
#elif defined(TGT_A71CH)
#define OPENSSL_ENGINE_EMBSE_ID "e2a71ch"
#elif defined (TGT_A70CM)
#define OPENSSL_ENGINE_EMBSE_ID "e2se"
#else
#error "Define a valid target Secure Element"
#endif

// Signature to indicate that the RSA/ECC key is a reference to a key stored in the Secure Element
#define EMBSE_REFKEY_ID            0xA5A6B5B6

void EngineEmbSe_Load(void);

#ifdef __cplusplus
}
#endif

#endif // AX_EMB_SE_ENGINE_H
