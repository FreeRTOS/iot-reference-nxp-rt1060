#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

ADD_SUBDIRECTORY(src)

IF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS)

    IF(
        WithRTOS_Default
        AND (WithApplet_SE05X
             OR WithApplet_A71CH
             OR WithApplet_A71CH_SIM)
    )
        IF(WithApplet_SE05X)
            ADD_SUBDIRECTORY(symmetric)
        ENDIF()
        IF(SSS_HAVE_HOSTCRYPTO_ANY)
            ADD_SUBDIRECTORY(hkdf)
        ENDIF()
        ADD_SUBDIRECTORY(md)
        ADD_SUBDIRECTORY(hmac)
        IF(SSS_HAVE_HOSTCRYPTO_ANY)
            ADD_SUBDIRECTORY(ecdh)
        ENDIF()
    ENDIF()

    IF(SSS_HAVE_ECC OR (WithApplet_None AND (WithHostCrypto_OPENSSL OR WithHostCrypto_MBEDTLS)))
        ADD_SUBDIRECTORY(ecc)
        IF(SSS_HAVE_TPM_BN OR (WithApplet_None AND (WithHostCrypto_OPENSSL OR WithHostCrypto_MBEDTLS)))
            ADD_SUBDIRECTORY(ecdaa)
        ENDIF()
        IF(SSS_HAVE_APPLET_SE05X_IOT)
            ADD_SUBDIRECTORY(attest_ecc)
            IF(SSS_HAVE_EC_MONT)
                ADD_SUBDIRECTORY(attest_mont)
            ENDIF()
        ENDIF()
    ENDIF()
    IF(SSS_HAVE_RSA OR (WithApplet_None AND (WithHostCrypto_OPENSSL OR WithHostCrypto_MBEDTLS)))
        IF(NOT SSS_HAVE_APPLET_SE051_UWB)
           ADD_SUBDIRECTORY(rsa)
        ENDIF()
    ENDIF()

    IF(WithKSDK)
        #No native mbedTLS Examples
    ELSE()
        IF(WithmbedTLS_ALT_SSS)
            ADD_SUBDIRECTORY(mbedtls)
        ENDIF()
    ENDIF()

ENDIF(NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS)
