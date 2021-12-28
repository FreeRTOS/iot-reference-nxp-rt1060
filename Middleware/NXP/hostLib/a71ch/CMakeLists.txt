#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

FILE(
    GLOB
    a71ch_sources
    inc/*.h
    src/*.c
    ../api/inc/*.h
    ../api/src/*.h
    ../api/src/A71HLSEWrapper.*
    ../api/src/ax_scp.*
    ../api/src/ax_sss_scp.*
    ../api/src/ax_util.*
    ../libCommon/hostCrypto/hcAsn.c
    ../libCommon/infra/a71_debug.c
    ../libCommon/infra/global_platf.*
    ../libCommon/infra/sm_connect.*
    ../libCommon/infra/nxLog_hostLib.*
    ../libCommon/scp/scp_a7x.*
)

#IF(WithSCP_SCP03_SSS)
#    FILE(
#        GLOB
#            scp_files
#            ../libCommon/scp/scp.*
#    )
#ENDIF()

IF(WithHostCrypto_MBEDTLS)
    SET(a71ch_mbedtls_sources ../libCommon/hostCrypto/axHostCryptombedtls.c
                              ../libCommon/hostCrypto/HostCryptoAPImbedtls.c
    )
    SET(a71ch_mbedtls_library mbedtls)
ENDIF()

IF(WithHostCrypto_OPENSSL)
    SET(a71ch_openssl_sources ../libCommon/hostCrypto/axHostCryptoOpenSSL.c
                              ../libCommon/hostCrypto/HostCryptoAPIOpenSSL.c
    )
ENDIF()

ADD_LIBRARY(
    a71ch
    ${a71ch_sources}
    ${a71ch_openssl_sources}
    ${a71ch_mbedtls_sources}
    ${scp_files}
)

# NOTE-MMA: Commented out SSS_APIs as this causes a circular dependency
# which makes it impossible to use shared libraries
TARGET_LINK_LIBRARIES(
    a71ch
    smCom
    ${a71ch_mbedtls_library}
    # SSS_APIs
)

TARGET_INCLUDE_DIRECTORIES(
    a71ch
    PUBLIC ../api/inc
    PUBLIC ../libCommon/scp
    PUBLIC inc
    PUBLIC ../libCommon/hostCrypto # FIXME : This must eventually not be needed because sss APIs should be enough
    PUBLIC ${SIMW_TOP_DIR}/sss/inc
)

IF(WithKSDK)
    TARGET_INCLUDE_DIRECTORIES(a71ch PUBLIC ${SIMW_TOP_DIR}/sss/port/ksdk)
ELSE()
    TARGET_INCLUDE_DIRECTORIES(a71ch PUBLIC ${SIMW_TOP_DIR}/sss/port/default)
ENDIF()

IF(WithHostCrypto_MBEDCRYPTO)
    TARGET_COMPILE_DEFINITIONS(
        a71ch
        PUBLIC MBEDCRYPTO # FIXME : Purnank : This must eventually not be needed because sss APIs should be enough
    )
ELSEIF(WithHostCrypto_MBEDTLS)
    TARGET_COMPILE_DEFINITIONS(
        a71ch PUBLIC MBEDTLS # FIXME : Purnank : This must eventually not be needed because sss APIs should be enough
    )
ENDIF()

IF(WithHostCrypto_OPENSSL)
    TARGET_COMPILE_DEFINITIONS(
        a71ch PUBLIC OPENSSL # FIXME : Purnank : This must eventually not be needed because sss APIs should be enough
    )
    INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
ENDIF()

TARGET_COMPILE_DEFINITIONS(a71ch PUBLIC SCP_MODE=C_MAC_C_ENC_R_MAC_R_ENC)

IF(WithSCP_SCP03_HostCrypto AND WithRTOS_Default)
    ADD_SUBDIRECTORY(ex)
    ADD_SUBDIRECTORY(ex_hlse)
    IF(NXPInternal)
        ADD_SUBDIRECTORY(tst)
    ENDIF()
ENDIF()

IF(WithHostCrypto_OPENSSL AND WithRTOS_Default)
    ADD_SUBDIRECTORY(app)
ENDIF()

IF(WithHost_LinuxLike OR WithHost_Android)
    INSTALL(TARGETS a71ch DESTINATION lib)
ENDIF()
