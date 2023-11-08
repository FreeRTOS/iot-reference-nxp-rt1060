/*
 * FreeRTOS V202111.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */

/**
 * @file tls_freertos.c
 * @brief TLS transport interface implementations. This implementation uses
 * mbedTLS.
 */

/* Standard includes. */
#include <string.h>

/* FreeRTOS includes. */
#include "FreeRTOS.h"

#include "core_pkcs11_config.h"

/* PKCS #11 includes. */
#include "core_pkcs11.h"

/* TLS transport header. */
#include "using_mbedtls.h"

#include "tcp_sockets_wrapper.h"

#include "pkcs11.h"
#include "core_pki_utils.h"


/**************************************************/
/******* DO NOT CHANGE the following order ********/
/**************************************************/

/* Logging related header files are required to be included in the following order:
 * 1. Include the header file "logging_levels.h".
 * 2. Define LIBRARY_LOG_NAME and  LIBRARY_LOG_LEVEL.
 * 3. Include the header file "logging_stack.h".
 */

/* Include header that defines log levels. */
#include "logging_levels.h"

/* Logging configuration for the Sockets. */
#ifndef LIBRARY_LOG_NAME
#define LIBRARY_LOG_NAME     "TlsTransport"
#endif
#ifndef LIBRARY_LOG_LEVEL
#define LIBRARY_LOG_LEVEL    LOG_ERROR
#endif

#include "logging.h"


/*-----------------------------------------------------------*/

/**
 * @brief Represents string to be logged when mbedTLS returned error
 * does not contain a high-level code.
 */
static const char * pNoHighLevelMbedTlsCodeStr = "<No-High-Level-Code>";

/**
 * @brief Represents string to be logged when mbedTLS returned error
 * does not contain a low-level code.
 */
static const char * pNoLowLevelMbedTlsCodeStr = "<No-Low-Level-Code>";

/**
 * @brief Utility for converting the high-level code in an mbedTLS error to string,
 * if the code-contains a high-level code; otherwise, using a default string.
 */
#define mbedtlsHighLevelCodeOrDefault( mbedTlsCode )       \
    ( mbedtls_high_level_strerr( mbedTlsCode ) != NULL ) ? \
    mbedtls_high_level_strerr( mbedTlsCode ) : pNoHighLevelMbedTlsCodeStr

/**
 * @brief Utility for converting the level-level code in an mbedTLS error to string,
 * if the code-contains a level-level code; otherwise, using a default string.
 */
#define mbedtlsLowLevelCodeOrDefault( mbedTlsCode )       \
    ( mbedtls_low_level_strerr( mbedTlsCode ) != NULL ) ? \
    mbedtls_low_level_strerr( mbedTlsCode ) : pNoLowLevelMbedTlsCodeStr

/*-----------------------------------------------------------*/

/**
 * @brief Initialize the mbed TLS structures in a network connection.
 *
 * @param[in] pSslContext The SSL context to initialize.
 */
static void sslContextInit( SSLContext_t * pSslContext );

/**
 * @brief Free the mbed TLS structures in a network connection.
 *
 * @param[in] pSslContext The SSL context to free.
 */
static void sslContextFree( SSLContext_t * pSslContext );

/*-----------------------------------------------------------*/

void * pvPortRealloc( void * pvPtr, size_t xSize );

/**
 * @brief Callback that wraps PKCS#11 using secure element for random number generation.
 *
 * @param[in] pvCtx Caller context.
 * @param[in] pucRandom Byte array to fill with random data.
 * @param[in] xRandomLength Length of byte array.
 *
 * @return Zero on success.
 */
static int generateRandomBytes( void * pvCtx,
                                unsigned char * pucRandom,
                                size_t xRandomLength );

/**
 * @brief Helper for reading the specified certificate object, if present,
 * out of storage, into RAM, and then into an mbedTLS certificate context
 * object.
 *
 * @param[in] pSslContext Caller TLS context.
 * @param[in] pcLabelName PKCS #11 certificate object label.
 * @param[in] xClass PKCS #11 certificate object class.
 * @param[out] pxCertificateContext Certificate context.
 *
 * @return Zero on success.
 */
static CK_RV readCertificateIntoContext( SSLContext_t * pSslContext,
                                         const char * pcLabelName,
                                         CK_OBJECT_CLASS xClass,
                                         mbedtls_x509_crt * pxCertificateContext );

/**
 * @brief Helper for setting up potentially hardware-based cryptographic context
 * for the client TLS certificate and private key.
 *
 * @param[in] Caller context.
 * @param[in] PKCS11 label which contains the desired private key.
 *
 * @return Zero on success.
 */
static CK_RV initializeClientKeys( SSLContext_t * pxCtx,
                                   const char * pcLabelName );

/**
 * @brief Sign a cryptographic hash with the private key.
 *
 * @param[in] pvContext Crypto context.
 * @param[in] xMdAlg Unused.
 * @param[in] pucHash Length in bytes of hash to be signed.
 * @param[in] uiHashLen Byte array of hash to be signed.
 * @param[out] pucSig RSA signature bytes.
 * @param[in] pxSigLen Length in bytes of signature buffer.
 * @param[in] piRng Unused.
 * @param[in] pvRng Unused.
 *
 * @return Zero on success.
 */
static int privateKeySigningCallback( void * pvContext,
                                      mbedtls_md_type_t xMdAlg,
                                      const unsigned char * pucHash,
                                      size_t xHashLen,
                                      unsigned char * pucSig,
                                      size_t * pxSigLen,
                                      int ( * piRng )( void *,
                                                       unsigned char *,
                                                       size_t ),
                                      void * pvRng );

/**
 * @brief Setup TLS by initializing contexts and setting configurations.
 *
 * @param[in] pNetworkContext Network context.
 * @param[in] pHostName Remote host name, used for server name indication.
 * @param[in] pNetworkCredentials TLS setup parameters.
 *
 * @return #TLS_TRANSPORT_SUCCESS, #TLS_TRANSPORT_INSUFFICIENT_MEMORY, #TLS_TRANSPORT_INVALID_CREDENTIALS,
 * or #TLS_TRANSPORT_INTERNAL_ERROR.
 */
static TlsTransportStatus_t tlsSetup( NetworkContext_t * pNetworkContext,
                                      const char * pHostName,
                                      const NetworkCredentials_t * pNetworkCredentials );

/**
 * @brief Sends data over +TCP sockets.
 *
 * @param[in] ctx The network context containing the socket handle.
 * @param[in] buf Buffer containing the bytes to send.
 * @param[in] len Number of bytes to send from the buffer.
 *
 * @return Number of bytes sent on success; else a negative value.
 */
int xwolfSSLBioTCPSocketWrapperSend( WOLFSSL * ssl,
                                     char * buf,
                                     int sz,
                                     void * ctx );


/**
 * @brief Receives data from +TCP socket.
 *
 * @param[in] ssl The wolfSSL network context containing the socket handle.
 * @param[out] buf Buffer to receive bytes into.
 * @param[in] len Number of bytes to receive from the network.
 * @param[in] ctx Not used.
 *
 * @return Number of bytes received if successful; Negative value on error.
 */
int xwolfSSLBioTCPSocketWrapperRecv( WOLFSSL * ssl,
                                     char * buf,
                                     int len,
                                     void * ctx );

/*-----------------------------------------------------------*/

static void sslContextInit( SSLContext_t * pSslContext )
{
    configASSERT( pSslContext != NULL );

    /*
    mbedtls_ssl_config_init( &( pSslContext->config ) );
    mbedtls_x509_crt_init( &( pSslContext->rootCa ) );
    mbedtls_x509_crt_init( &( pSslContext->clientCert ) );
    mbedtls_ssl_init( &( pSslContext->context ) );
    */

    xInitializePkcs11Session( &( pSslContext->xP11Session ) );
    C_GetFunctionList( &( pSslContext->pxP11FunctionList ) );
}
/*-----------------------------------------------------------*/

static void sslContextFree( SSLContext_t * pSslContext )
{
    configASSERT( pSslContext != NULL );

    /*
    mbedtls_ssl_free( &( pSslContext->context ) );
    mbedtls_x509_crt_free( &( pSslContext->rootCa ) );
    mbedtls_x509_crt_free( &( pSslContext->clientCert ) );
    mbedtls_ssl_config_free( &( pSslContext->config ) );
    */

    pSslContext->pxP11FunctionList->C_CloseSession( pSslContext->xP11Session );
}
/*-----------------------------------------------------------*/

static CK_RV readCertificateIntoContext( SSLContext_t * pSslContext,
                                         const char * pcLabelName,
                                         CK_OBJECT_CLASS xClass,
                                         mbedtls_x509_crt * pxCertificateContext )
{
    CK_RV xResult = CKR_OK;
    CK_ATTRIBUTE xTemplate = { 0 };
    CK_OBJECT_HANDLE xCertObj = 0;

    /* Get the handle of the certificate. */
    xResult = xFindObjectWithLabelAndClass( pSslContext->xP11Session,
                                            ( char * ) pcLabelName,
                                            strnlen( pcLabelName,
                                                     pkcs11configMAX_LABEL_LENGTH ),
                                            xClass,
                                            &xCertObj );

    if( ( CKR_OK == xResult ) && ( xCertObj == CK_INVALID_HANDLE ) )
    {
        xResult = CKR_OBJECT_HANDLE_INVALID;
    }

    /* Query the certificate size. */
    if( CKR_OK == xResult )
    {
        xTemplate.type = CKA_VALUE;
        xTemplate.ulValueLen = 0;
        xTemplate.pValue = NULL;
        xResult = pSslContext->pxP11FunctionList->C_GetAttributeValue( pSslContext->xP11Session,
                                                                       xCertObj,
                                                                       &xTemplate,
                                                                       1 );
    }

    /* Create a buffer for the certificate. */
    if( CKR_OK == xResult )
    {
        xTemplate.pValue = pvPortMalloc( xTemplate.ulValueLen );

        if( NULL == xTemplate.pValue )
        {
            xResult = CKR_HOST_MEMORY;
        }
    }

    /* Export the certificate. */
    if( CKR_OK == xResult )
    {
        xResult = pSslContext->pxP11FunctionList->C_GetAttributeValue( pSslContext->xP11Session,
                                                                       xCertObj,
                                                                       &xTemplate,
                                                                       1 );
    }

    /* Decode the certificate. */
    if( CKR_OK == xResult )
    {
        xResult = mbedtls_x509_crt_parse( pxCertificateContext,
                                          ( const unsigned char * ) xTemplate.pValue,
                                          xTemplate.ulValueLen );
       // wolfSSL_CTX_use_certificate_buffer();
    }

    /* Free memory. */
    vPortFree( xTemplate.pValue );

    return xResult;
}

/*----------------------------------------------------------*/

/**
 * @brief Helper for setting up potentially hardware-based cryptographic context
 * for the client TLS certificate and private key.
 *
 * @param[in] Caller context.
 * @param[in] PKCS11 label which contains the desired private key.
 *
 * @return Zero on success.
 */
static CK_RV initializeClientKeys( SSLContext_t * pxCtx,
                                   const char * pcLabelName )
{
    CK_RV xResult = CKR_OK;
    CK_SLOT_ID * pxSlotIds = NULL;
    CK_ULONG xCount = 0;
    CK_ATTRIBUTE xTemplate[ 2 ];
    mbedtls_pk_type_t xKeyAlgo = ( mbedtls_pk_type_t ) ~0;

    /* Get the PKCS #11 module/token slot count. */
    if( CKR_OK == xResult )
    {
        xResult = ( BaseType_t ) pxCtx->pxP11FunctionList->C_GetSlotList( CK_TRUE,
                                                                          NULL,
                                                                          &xCount );
    }

    /* Allocate memory to store the token slots. */
    if( CKR_OK == xResult )
    {
        pxSlotIds = ( CK_SLOT_ID * ) pvPortMalloc( sizeof( CK_SLOT_ID ) * xCount );

        if( NULL == pxSlotIds )
        {
            xResult = CKR_HOST_MEMORY;
        }
    }

    /* Get all of the available private key slot identities. */
    if( CKR_OK == xResult )
    {
        xResult = ( BaseType_t ) pxCtx->pxP11FunctionList->C_GetSlotList( CK_TRUE,
                                                                          pxSlotIds,
                                                                          &xCount );
    }

    /* Put the module in authenticated mode. */
    if( CKR_OK == xResult )
    {
        xResult = ( BaseType_t ) pxCtx->pxP11FunctionList->C_Login( pxCtx->xP11Session,
                                                                    CKU_USER,
                                                                    ( CK_UTF8CHAR_PTR ) configPKCS11_DEFAULT_USER_PIN,
                                                                    sizeof( configPKCS11_DEFAULT_USER_PIN ) - 1 );
    }

    if( CKR_OK == xResult )
    {
        /* Get the handle of the device private key. */
        xResult = xFindObjectWithLabelAndClass( pxCtx->xP11Session,
                                                ( char * ) pcLabelName,
                                                strnlen( pcLabelName,
                                                         pkcs11configMAX_LABEL_LENGTH ),
                                                CKO_PRIVATE_KEY,
                                                &pxCtx->xP11PrivateKey );
    }

    if( ( CKR_OK == xResult ) && ( pxCtx->xP11PrivateKey == CK_INVALID_HANDLE ) )
    {
        xResult = CK_INVALID_HANDLE;
        LogError( ( "Could not find private key." ) );
    }

    /* Query the device private key type. */
    if( xResult == CKR_OK )
    {
        xTemplate[ 0 ].type = CKA_KEY_TYPE;
        xTemplate[ 0 ].pValue = &pxCtx->xKeyType;
        xTemplate[ 0 ].ulValueLen = sizeof( CK_KEY_TYPE );
        xResult = pxCtx->pxP11FunctionList->C_GetAttributeValue( pxCtx->xP11Session,
                                                                 pxCtx->xP11PrivateKey,
                                                                 xTemplate,
                                                                 1 );
    }

    /* Map the PKCS #11 key type to an mbedTLS algorithm. */
    if( xResult == CKR_OK )
    {
        switch( pxCtx->xKeyType )
        {
            case CKK_RSA:
                xKeyAlgo = MBEDTLS_PK_RSA;
                break;

            case CKK_EC:
                xKeyAlgo = MBEDTLS_PK_ECKEY;
                break;

            default:
                xResult = CKR_ATTRIBUTE_VALUE_INVALID;
                break;
        }
    }

    /* Map the mbedTLS algorithm to its internal metadata. */
    if( xResult == CKR_OK )
    {
        memcpy( &pxCtx->privKeyInfo, mbedtls_pk_info_from_type( xKeyAlgo ), sizeof( mbedtls_pk_info_t ) );

        /* Assign unimplemented function pointers to NULL */
        pxCtx->privKeyInfo.get_bitlen = NULL;
        pxCtx->privKeyInfo.verify_func = NULL;
#if defined( MBEDTLS_ECDSA_C ) && defined( MBEDTLS_ECP_RESTARTABLE )
        pxCtx->privKeyInfo.verify_rs_func = NULL;
        pxCtx->privKeyInfo.sign_rs_func = NULL;
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
        pxCtx->privKeyInfo.decrypt_func = NULL;
        pxCtx->privKeyInfo.encrypt_func = NULL;
        pxCtx->privKeyInfo.check_pair_func = NULL;
        pxCtx->privKeyInfo.ctx_alloc_func = NULL;
        pxCtx->privKeyInfo.ctx_free_func = NULL;
#if defined( MBEDTLS_ECDSA_C ) && defined( MBEDTLS_ECP_RESTARTABLE )
        pxCtx->privKeyInfo.rs_alloc_func = NULL;
        pxCtx->privKeyInfo.rs_free_func = NULL;
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
        pxCtx->privKeyInfo.debug_func = NULL;

        pxCtx->privKeyInfo.sign_func = privateKeySigningCallback;
        pxCtx->privKey.pk_info = &pxCtx->privKeyInfo;
        pxCtx->privKey.pk_ctx = pxCtx;
    }

    /* Free memory. */
    vPortFree( pxSlotIds );

    return xResult;
}

/*-----------------------------------------------------------*/

static int privateKeySigningCallback( void * pvContext,
                                      mbedtls_md_type_t xMdAlg,
                                      const unsigned char * pucHash,
                                      size_t xHashLen,
                                      unsigned char * pucSig,
                                      size_t * pxSigLen,
                                      int ( * piRng )( void *,
                                                       unsigned char *,
                                                       size_t ),
                                      void * pvRng )
{
    CK_RV xResult = CKR_OK;
    int iFinalResult = 0;
    SSLContext_t * pxTLSContext = ( SSLContext_t * ) pvContext;
    CK_MECHANISM xMech = { 0 };
    CK_BYTE xToBeSigned[ 256 ];
    CK_ULONG xToBeSignedLen = sizeof( xToBeSigned );

    /* Unreferenced parameters. */
    ( void ) ( piRng );
    ( void ) ( pvRng );
    ( void ) ( xMdAlg );

    /* Sanity check buffer length. */
    if( xHashLen > sizeof( xToBeSigned ) )
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    /* Format the hash data to be signed. */
    if( CKK_RSA == pxTLSContext->xKeyType )
    {
        xMech.mechanism = CKM_RSA_PKCS;

        /* mbedTLS expects hashed data without padding, but PKCS #11 C_Sign function performs a hash
         * & sign if hash algorithm is specified.  This helper function applies padding
         * indicating data was hashed with SHA-256 while still allowing pre-hashed data to
         * be provided. */
        xResult = vAppendSHA256AlgorithmIdentifierSequence( ( uint8_t * ) pucHash, xToBeSigned );
        xToBeSignedLen = pkcs11RSA_SIGNATURE_INPUT_LENGTH;
    }
    else if( CKK_EC == pxTLSContext->xKeyType )
    {
        xMech.mechanism = CKM_ECDSA;
        memcpy( xToBeSigned, pucHash, xHashLen );
        xToBeSignedLen = xHashLen;
    }
    else
    {
        xResult = CKR_ARGUMENTS_BAD;
    }

    if( CKR_OK == xResult )
    {
        /* Use the PKCS#11 module to sign. */
        xResult = pxTLSContext->pxP11FunctionList->C_SignInit( pxTLSContext->xP11Session,
                                                               &xMech,
                                                               pxTLSContext->xP11PrivateKey );
    }

    if( CKR_OK == xResult )
    {
        *pxSigLen = sizeof( xToBeSigned );
        xResult = pxTLSContext->pxP11FunctionList->C_Sign( ( CK_SESSION_HANDLE ) pxTLSContext->xP11Session,
                                                           xToBeSigned,
                                                           xToBeSignedLen,
                                                           pucSig,
                                                           ( CK_ULONG_PTR ) pxSigLen );
    }

    if( ( xResult == CKR_OK ) && ( CKK_EC == pxTLSContext->xKeyType ) )
    {
        /* PKCS #11 for P256 returns a 64-byte signature with 32 bytes for R and 32 bytes for S.
         * This must be converted to an ASN.1 encoded array. */
        if( *pxSigLen != pkcs11ECDSA_P256_SIGNATURE_LENGTH )
        {
            xResult = CKR_FUNCTION_FAILED;
        }

        if( xResult == CKR_OK )
        {
            PKI_pkcs11SignatureTombedTLSSignature( pucSig, pxSigLen );
        }
    }

    if( xResult != CKR_OK )
    {
        LogError( ( "Failed to sign message using PKCS #11 with error code %02X.", xResult ) );
        iFinalResult = -1;
    }

    return iFinalResult;
}

/*-----------------------------------------------------------*/

int EccSignCallback( WOLFSSL* ssl,
                     const unsigned char* in, unsigned int inSz,
                     unsigned char* out, word32* outSz,
                     const unsigned char* keyDer, unsigned int keySz,
                     void* ctx)
{
	/* TODO: Add code to actually add ECC Signing. */
	return 0;
}

/*-----------------------------------------------------------*/

static int generateRandomBytes( void * pvCtx,
                                unsigned char * pucRandom,
                                size_t xRandomLength )
{
    /* Must cast from void pointer to conform to mbed TLS API. */
    SSLContext_t * pxCtx = ( SSLContext_t * ) pvCtx;
    CK_RV xResult;

    xResult = pxCtx->pxP11FunctionList->C_GenerateRandom( pxCtx->xP11Session, pucRandom, xRandomLength );

    if( xResult != CKR_OK )
    {
        LogError( ( "Failed to generate random bytes from the PKCS #11 module." ) );
    }

    return xResult;
}

int rand_gen_seed( byte* output,
                   word32 sz )
{
	/*
	 * Note that this is just an example, the seed in production code should be
	 * provided using a source with more entropy which should be hard to predict.
	 */
	static unsigned char RNGSeed = 0x23;
	for( word32 i = 0; i < sz; i++ )
	{
		output[ i ] = RNGSeed++;
	}

	return 0;
}

/**
 * Return a valid value only when the initial pointer is NULL. Otherwise,
 * the function will behave as if there is no memory and will return NULL.
 */
void * pvPortRealloc( void * pvPtr, size_t xSize )
{
	void * pvReturn = NULL;
	if( pvPtr == NULL )
	{
		pvReturn = pvPortMalloc( xSize );
	}

	return pvReturn;
}

static TlsTransportStatus_t tlsSetup( NetworkContext_t * pNetworkContext,
                                      const char * pHostName,
                                      const NetworkCredentials_t * pNetworkCredentials )
{
    TlsTransportStatus_t returnStatus = TLS_TRANSPORT_SUCCESS;
    int32_t mbedtlsError = 0;
    CK_RV xResult = CKR_OK;
    char buffer[ WOLFSSL_MAX_ERROR_SZ ];

    configASSERT( pNetworkContext != NULL );
    configASSERT( pHostName != NULL );
    configASSERT( pNetworkCredentials != NULL );
    configASSERT( pNetworkCredentials->pRootCa != NULL );
    configASSERT( pNetworkCredentials->pClientCertLabel != NULL );
    configASSERT( pNetworkCredentials->pPrivateKeyLabel != NULL );

    /* Initialize the TLS context structures. */
    sslContextInit( &( pNetworkContext->sslContext ) );

    pNetworkContext->sslContext.wolfSSLContext = wolfSSL_CTX_new( wolfSSLv23_client_method_ex(NULL) );

    pNetworkContext->sslContext.wolfssl = wolfSSL_new( pNetworkContext->sslContext.wolfSSLContext );

    /* Set the socket pointer in the context. */
    wolfSSL_SetIOReadCtx( pNetworkContext->sslContext.wolfssl, pNetworkContext->tcpSocket );
    wolfSSL_SetIOWriteCtx( pNetworkContext->sslContext.wolfssl, pNetworkContext->tcpSocket );


    /*mbedtlsError = mbedtls_ssl_config_defaults( &( pNetworkContext->sslContext.config ),
                                                MBEDTLS_SSL_IS_CLIENT,
                                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                                MBEDTLS_SSL_PRESET_DEFAULT );
    */

    /* Set memory allocation/freeing functions */
    wolfSSL_SetAllocators( pvPortMalloc, vPortFree, pvPortRealloc );
    // Not required as this is present in wolfssl/wolfssl/wolfcrypt/settings.h ??

    if( pNetworkContext->sslContext.wolfSSLContext != NULL )
	{
		wolfSSL_CTX_SetEccSignCb( pNetworkContext->sslContext.wolfSSLContext, EccSignCallback );

	}

    /*if( mbedtlsError != 0 )
    {
        LogError( ( "Failed to set default SSL configuration: mbedTLSError= %s : %s.",
                    mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                    mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );

        // Per mbed TLS docs, mbedtls_ssl_config_defaults only fails on memory allocation.
        returnStatus = TLS_TRANSPORT_INSUFFICIENT_MEMORY;
    }*/

    if( returnStatus == TLS_TRANSPORT_SUCCESS )
    {
        /* Set up the certificate security profile, starting from the default value. */
        pNetworkContext->sslContext.certProfile = mbedtls_x509_crt_profile_default;

        /* test.mosquitto.org only provides a 1024-bit RSA certificate, which is
         * not acceptable by the default mbed TLS certificate security profile.
         * For the purposes of this demo, allow the use of 1024-bit RSA certificates.
         * This block should be removed otherwise. */
        if( strncmp( pHostName, "test.mosquitto.org", strlen( pHostName ) ) == 0 )
        {
            pNetworkContext->sslContext.certProfile.rsa_min_bitlen = 1024;
        }

        /* Set SSL authmode and the RNG context. */
        /* mbedtls_ssl_conf_authmode( &( pNetworkContext->sslContext.config ),
                                   MBEDTLS_SSL_VERIFY_REQUIRED );

        // Done by wolfSSL by default. SSL_VERIFY_PEER is on by default in client mode.
        wolfSSL_set_verify();
        */

        /* mbedtls_ssl_conf_rng( &( pNetworkContext->sslContext.config ),
                              generateRandomBytes,
                              &pNetworkContext->sslContext );
          // Done in wolfSSL thru custom callback CUSTOM_RAND_GENERATE_SEED.
         */


        /* mbedtls_ssl_conf_cert_profile( &( pNetworkContext->sslContext.config ),
                                       &( pNetworkContext->sslContext.certProfile ) );
        */

        /* Parse the server root CA certificate into the SSL context. */
        /* mbedtlsError = mbedtls_x509_crt_parse( &( pNetworkContext->sslContext.rootCa ),
                                               pNetworkCredentials->pRootCa,
                                               pNetworkCredentials->rootCaSize ); */

        pNetworkContext->sslContext.wolfsslRootCAFormat = WOLFSSL_FILETYPE_PEM;
        mbedtlsError = wolfSSL_CTX_use_certificate_buffer( pNetworkContext->sslContext.wolfSSLContext,
                                                           pNetworkCredentials->pRootCa,
                                                           pNetworkCredentials->rootCaSize,
											               pNetworkContext->sslContext.wolfsslRootCAFormat );

        if( mbedtlsError != SSL_SUCCESS )
        {
        	wc_ErrorString( mbedtlsError, buffer );
            LogError( ( "Failed to parse server root CA certificate: Error= %s", buffer ) );

            returnStatus = TLS_TRANSPORT_INVALID_CREDENTIALS;
        }
        else
        {
            /*
            mbedtls_ssl_conf_ca_chain( &( pNetworkContext->sslContext.config ),
                                       &( pNetworkContext->sslContext.rootCa ),
                                       NULL );
            */
        	returnStatus = wolfSSL_CTX_load_verify_buffer( pNetworkContext->sslContext.wolfSSLContext,
                                            pNetworkCredentials->pRootCa,
                                            pNetworkCredentials->rootCaSize,
                                            pNetworkContext->sslContext.wolfsslRootCAFormat );
        }
    }

    if( returnStatus == TLS_TRANSPORT_SUCCESS )
    {
        /* Setup the client private key. */
        xResult = initializeClientKeys( &( pNetworkContext->sslContext ),
                                        pNetworkCredentials->pPrivateKeyLabel );

        if( xResult != CKR_OK )
        {
            LogError( ( "Failed to setup key handling by PKCS #11." ) );

            returnStatus = TLS_TRANSPORT_INVALID_CREDENTIALS;
        }
        else
        {
            /* Setup the client certificate. */
            xResult = readCertificateIntoContext( &( pNetworkContext->sslContext ),
                                                  pNetworkCredentials->pClientCertLabel,
                                                  CKO_CERTIFICATE,
                                                  &( pNetworkContext->sslContext.clientCert ) );

            if( xResult != CKR_OK )
            {
                LogError( ( "Failed to get certificate from PKCS #11 module." ) );

                returnStatus = TLS_TRANSPORT_INVALID_CREDENTIALS;
            }
            else
            {
                ( void ) mbedtls_ssl_conf_own_cert( &( pNetworkContext->sslContext.config ),
                                                    &( pNetworkContext->sslContext.clientCert ),
                                                    &( pNetworkContext->sslContext.privKey ) );
                /* wolfSSL_use_certificate( pNetworkContext->sslContext.wolfssl,
                	 	                 pNetworkContext->sslContext ); */
            }
        }
    }

    if( ( returnStatus == TLS_TRANSPORT_SUCCESS ) && ( pNetworkCredentials->pAlpnProtos != NULL ) )
    {
        /* Include an application protocol list in the TLS ClientHello
         * message. */
        mbedtlsError = mbedtls_ssl_conf_alpn_protocols( &( pNetworkContext->sslContext.config ),
                                                        pNetworkCredentials->pAlpnProtos );

        if( mbedtlsError != 0 )
        {
            LogError( ( "Failed to configure ALPN protocol in mbed TLS: mbedTLSError= %s : %s.",
                        mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                        mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );

            returnStatus = TLS_TRANSPORT_INTERNAL_ERROR;
        }
    }

    if( returnStatus == TLS_TRANSPORT_SUCCESS )
    {
        /* Initialize the mbed TLS secured connection context. */
        mbedtlsError = mbedtls_ssl_setup( &( pNetworkContext->sslContext.context ),
                                          &( pNetworkContext->sslContext.config ) );

        if( mbedtlsError != 0 )
        {
            LogError( ( "Failed to set up mbed TLS SSL context: mbedTLSError= %s : %s.",
                        mbedtlsHighLevelCodeOrDefault( mbedtlsError ),
                        mbedtlsLowLevelCodeOrDefault( mbedtlsError ) ) );

            returnStatus = TLS_TRANSPORT_INTERNAL_ERROR;
        }
        else
        {
            /* Set the underlying IO for the TLS connection. */

            /* MISRA Rule 11.2 flags the following line for casting the second
             * parameter to void *. This rule is suppressed because
             * #mbedtls_ssl_set_bio requires the second parameter as void *.
             */
            /* coverity[misra_c_2012_rule_11_2_violation] */
            /*mbedtls_ssl_set_bio( &( pNetworkContext->sslContext.context ),
                                 ( void * ) pNetworkContext->tcpSocket,
								 xMbedTLSBioTCPSocketsWrapperSend,
								 xMbedTLSBioTCPSocketsWrapperRecv,
                                 NULL );*/

            wolfSSL_SetIORecv( pNetworkContext->sslContext.wolfSSLContext, xwolfSSLBioTCPSocketWrapperRecv );
            wolfSSL_SetIOSend( pNetworkContext->sslContext.wolfSSLContext, xwolfSSLBioTCPSocketWrapperSend );
        }
    }

    if( returnStatus == TLS_TRANSPORT_SUCCESS )
    {
        /* Enable SNI if requested. */
        if( pNetworkCredentials->disableSni == pdFALSE )
        {
        	mbedtlsError = wolfSSL_CTX_UseSNI( pNetworkContext->sslContext.wolfSSLContext,
        			            WOLFSSL_SNI_HOST_NAME,
								pHostName,
								strlen( pHostName ) );

            if( mbedtlsError != WOLFSSL_SUCCESS )
            {
            	wc_ErrorString( mbedtlsError, buffer );
                LogError( ( "Failed to set server name: Error= %s",
                            buffer ) );

                returnStatus = TLS_TRANSPORT_INTERNAL_ERROR;
            }
        }
    }

    if( returnStatus == TLS_TRANSPORT_SUCCESS )
    {
        /* Perform the TLS handshake. */
    	mbedtlsError = wolfSSL_connect( pNetworkContext->sslContext.wolfssl );

        if( mbedtlsError != 0 )
        {
        	mbedtlsError = wolfSSL_get_error( pNetworkContext->sslContext.wolfssl,
                                              mbedtlsError );
        	wolfSSL_ERR_error_string( mbedtlsError, buffer );
            LogError( ( "Failed to perform TLS handshake: Error= %s",
                        buffer ) );

            returnStatus = TLS_TRANSPORT_HANDSHAKE_FAILED;
        }
    }

    if( returnStatus != TLS_TRANSPORT_SUCCESS )
    {
        sslContextFree( &( pNetworkContext->sslContext ) );
    }
    else
    {
        LogInfo( ( "(Network connection %p) TLS handshake successful.",
                   pNetworkContext ) );
    }

    return returnStatus;
}

int xwolfSSLBioTCPSocketWrapperSend( WOLFSSL *ssl,
                                     char *buf,
                                     int len,
                                     void * ctx )
{
    int32_t xReturnStatus;
    Socket_t xSocket = ( Socket_t ) ctx;

    configASSERT( ctx != NULL );
    configASSERT( buf != NULL );

    ( void ) ssl;

    xReturnStatus = TCP_Sockets_Send( xSocket, buf, len );

    if( xReturnStatus <= 0 )
	{
		if( xReturnStatus == 0 )
		{
			xReturnStatus = WOLFSSL_CBIO_ERR_WANT_WRITE;
		}
		else if( xReturnStatus == -pdFREERTOS_ERRNO_EWOULDBLOCK )
		{
			xReturnStatus = WOLFSSL_CBIO_ERR_WANT_WRITE;
		}
		else if( xReturnStatus == -pdFREERTOS_ERRNO_ENOTCONN )
		{
			xReturnStatus = WOLFSSL_CBIO_ERR_CONN_CLOSE;
		}
		else
		{
			/* Do nothing. */
		}
	}
	return xReturnStatus;
}

/**
 * @brief Receives data from TCP socket.
 *
 * @param[in] ctx The network context containing the socket handle.
 * @param[out] buf Buffer to receive bytes into.
 * @param[in] len Number of bytes to receive from the network.
 *
 * @return Number of bytes received if successful; Negative value on error.
 */
int xwolfSSLBioTCPSocketWrapperRecv( WOLFSSL *ssl,
                                     char *buf,
                                     int len,
                                     void *ctx )
{
    int32_t xReturnStatus;
    Socket_t xSocket = (Socket_t)ctx;

    configASSERT( ctx != NULL );
    configASSERT( buf != NULL );

    ( void ) ssl;

    xReturnStatus = TCP_Sockets_Recv( xSocket, buf, len );

    if( xReturnStatus <= 0 )
	{
		if (xReturnStatus == 0)  /* timeout */
		{
			xReturnStatus = WOLFSSL_CBIO_ERR_WANT_READ;
		}
		else if (xReturnStatus == -pdFREERTOS_ERRNO_EWOULDBLOCK)
		{
			xReturnStatus = WOLFSSL_CBIO_ERR_WANT_READ;
		}
		else if (xReturnStatus == -pdFREERTOS_ERRNO_ENOTCONN)
		{
			xReturnStatus = WOLFSSL_CBIO_ERR_CONN_CLOSE;
		}
		else
		{
			/* Do nothing. */
		}
	}
	return xReturnStatus;
}

/*-----------------------------------------------------------*/
TlsTransportStatus_t TLS_FreeRTOS_Connect( NetworkContext_t * pNetworkContext,
                                           const char * pHostName,
                                           uint16_t port,
                                           const NetworkCredentials_t * pNetworkCredentials,
                                           uint32_t receiveTimeoutMs,
                                           uint32_t sendTimeoutMs )
{
    TlsTransportStatus_t returnStatus = TLS_TRANSPORT_SUCCESS;
    BaseType_t socketStatus;
    BaseType_t isSocketConnected;
    static uint8_t wolfSSLInitDone = 0;

    if( ( pNetworkContext == NULL ) ||
        ( pHostName == NULL ) ||
        ( pNetworkCredentials == NULL ) )
    {
        LogError( ( "Invalid input parameter(s): Arguments cannot be NULL. pNetworkContext=%p, "
                    "pHostName=%p, pNetworkCredentials=%p.",
                    pNetworkContext,
                    pHostName,
                    pNetworkCredentials ) );
        returnStatus = TLS_TRANSPORT_INVALID_PARAMETER;
    }
    else if( ( pNetworkCredentials->pRootCa == NULL ) )
    {
        LogError( ( "pRootCa cannot be NULL." ) );
        returnStatus = TLS_TRANSPORT_INVALID_PARAMETER;
    }
    else
    {
        /* Empty else for MISRA 15.7 compliance. */
    }

    /* Establish a TCP connection with the server. */
    if( returnStatus == TLS_TRANSPORT_SUCCESS )
    {
        socketStatus = TCP_Sockets_Connect( &( pNetworkContext->tcpSocket ),
  	                                        pHostName,
   	                                        port,
   	                                        receiveTimeoutMs,
   	                                        sendTimeoutMs );

        if( socketStatus < 0 )
        {
            returnStatus = TLS_TRANSPORT_CONNECT_FAILURE;
        }
        else
        {
        	isSocketConnected = pdTRUE;
        }
    }

    /* Initialize TLS contexts and set credentials. */
    if( returnStatus == TLS_TRANSPORT_SUCCESS )
    {
    	if( wolfSSLInitDone == 0 )
		{
			if( wolfSSL_Init() == SSL_SUCCESS )
			{
				wolfSSLInitDone = 1;
			}
		}

    	if( wolfSSLInitDone == 1 )
    	{
            returnStatus = tlsSetup( pNetworkContext, pHostName, pNetworkCredentials );
    	}
    	else
    	{
    		returnStatus = -1;
    	}
    }

    /* Clean up on failure. */
    if( returnStatus != TLS_TRANSPORT_SUCCESS )
    {
        if( ( pNetworkContext != NULL ) && ( isSocketConnected == pdTRUE ) )
        {
            TCP_Sockets_Disconnect( pNetworkContext->tcpSocket );
            pNetworkContext->tcpSocket = NULL;
        }
    }
    else
    {
        LogInfo( ( "(Network connection %p) Connection to %s established.",
                   pNetworkContext,
                   pHostName ) );
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

void TLS_FreeRTOS_Disconnect( NetworkContext_t * pNetworkContext )
{
    BaseType_t tlsStatus = 0;

    if( pNetworkContext != NULL )
    {
        /* Attempting to terminate TLS connection. */
        tlsStatus = ( BaseType_t ) mbedtls_ssl_close_notify( &( pNetworkContext->sslContext.context ) );

        /* Ignore the WANT_READ and WANT_WRITE return values. */
        if( ( tlsStatus != ( BaseType_t ) MBEDTLS_ERR_SSL_WANT_READ ) &&
            ( tlsStatus != ( BaseType_t ) MBEDTLS_ERR_SSL_WANT_WRITE ) )
        {
            if( tlsStatus == 0 )
            {
                LogInfo( ( "(Network connection %p) TLS close-notify sent.",
                           pNetworkContext ) );
            }
            else
            {
                LogError( ( "(Network connection %p) Failed to send TLS close-notify: mbedTLSError= %s : %s.",
                            pNetworkContext,
                            mbedtlsHighLevelCodeOrDefault( tlsStatus ),
                            mbedtlsLowLevelCodeOrDefault( tlsStatus ) ) );
            }
        }
        else
        {
            /* WANT_READ and WANT_WRITE can be ignored. Logging for debugging purposes. */
            LogInfo( ( "(Network connection %p) TLS close-notify sent; received %s as the TLS status can be ignored for close-notify.",
                       pNetworkContext,
                       mbedtlsHighLevelCodeOrDefault( tlsStatus ) ) );
        }

        /* Close connection */
        TCP_Sockets_Disconnect( pNetworkContext->tcpSocket );

        /* Free mbed TLS contexts. */
        sslContextFree( &( pNetworkContext->sslContext ) );
    }
}
/*-----------------------------------------------------------*/

int32_t TLS_FreeRTOS_Recv( NetworkContext_t * pNetworkContext,
                           void * pBuffer,
                           size_t bytesToRecv )
{
    int32_t tlsStatus = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    char buffer[ WOLFSSL_MAX_ERROR_SZ ];

    if( ( pNetworkContext != NULL ) && ( pBuffer != NULL ) && ( bytesToRecv > 0 ) )
    {
        tlsStatus = ( int32_t ) wolfSSL_read( pNetworkContext->sslContext.wolfssl,
                                              pBuffer,
				                              bytesToRecv );

        if( tlsStatus == 0 )
		{
			tlsStatus = wolfSSL_get_error( pNetworkContext->sslContext.wolfssl, tlsStatus );
			wolfSSL_ERR_error_string( tlsStatus, buffer );

            LogDebug( ( "Failed to read data. However, a read can be retried on this error. "
                        "Error= %s.",
						buffer ) );
        }
        else if( tlsStatus < 0 )
        {
        	tlsStatus = wolfSSL_get_error( pNetworkContext->sslContext.wolfssl, tlsStatus );
			wolfSSL_ERR_error_string(tlsStatus, buffer);

			LogError( ( "Failed to recv data:  Error= %s.",
						buffer ) );
        }
        else
        {
            /* Empty else marker. */
        }
    }

    return tlsStatus;
}
/*-----------------------------------------------------------*/

int32_t TLS_FreeRTOS_Send( NetworkContext_t * pNetworkContext,
                           const void * pBuffer,
                           size_t bytesToSend )
{
    int32_t tlsStatus = MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    char buffer[ WOLFSSL_MAX_ERROR_SZ ];

    if( ( pNetworkContext != NULL ) && ( pBuffer != NULL ) && ( bytesToSend > 0 ) )
    {
    	tlsStatus = wolfSSL_write( pNetworkContext->sslContext.wolfssl,
                       pBuffer,
                       bytesToSend );
        /*tlsStatus = ( int32_t ) mbedtls_ssl_write( &( pNetworkContext->sslContext.context ),
                                                   pBuffer,
                                                   bytesToSend );*/

        if( tlsStatus == 0 )
        {
        	tlsStatus = wolfSSL_get_error( pNetworkContext->sslContext.wolfssl, tlsStatus );
        	wolfSSL_ERR_error_string(tlsStatus, buffer);

            LogDebug( ( "Failed to send data. However, send can be retried on this error. "
                        "Error= %s.",
                        buffer ) );
        }
        else if( tlsStatus < 0 )
        {
        	tlsStatus = wolfSSL_get_error( pNetworkContext->sslContext.wolfssl, tlsStatus );
        	wolfSSL_ERR_error_string(tlsStatus, buffer);

            LogError( ( "Failed to send data:  Error= %s.",
                        buffer ) );
        }
        else
        {
            /* Empty else marker. */
        }
    }

    return tlsStatus;
}
/*-----------------------------------------------------------*/
