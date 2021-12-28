#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

IF(WithApplet_A71CH OR WithApplet_A71CH_SIM)
    ADD_SUBDIRECTORY(a71ch)
ENDIF()

IF(WithApplet_SE05X)
    ADD_SUBDIRECTORY(se05x)
ENDIF()

IF(
    WithHost_PCLinux
    OR WithHost_iMXLinux
    OR WithHost_Raspbian
    OR WithHost_Android
    OR WithHost_Cygwin # TMP
)
    IF(
        WithSMCOM_SCI2C
        OR WithSMCOM_T1oI2C
        OR WithSMCOM_T1oI2C_GP1_0
        OR WithSMCOM_JRCP_V2 # TMP
    )
        ADD_SUBDIRECTORY(rjct)
        IF(WithApplet_SE05X OR WithApplet_A71CH OR WithApplet_A71CH_SIM)
            ADD_SUBDIRECTORY(accessManager)
        ENDIF()
    ENDIF()
ENDIF()

ADD_SUBDIRECTORY(libCommon)

SET(HAVE_A7X_UTILS OFF)

IF(WithApplet_A71XX OR WithApplet_SE050_EAR)
    PROJECT(a7x_utils)
    SET(HAVE_A7X_UTILS ON)

    IF(WithApplet_A71CH OR WithApplet_A71CH_SIM)
        FILE(
            GLOB
            a7ch_cl_util_file
            tstUtil/tst_a71ch_util.c
        )
    ENDIF()
    IF(WithApplet_A71CL OR WithApplet_SE050_L)
        FILE(
            GLOB
            a7ch_cl_util_file
            tstUtil/tst_a71cl_util.c
            libCommon/infra/sm_connect.*
            libCommon/infra/global_platf.*
            libCommon/scp/scp.c
        )
    ENDIF()
    FILE(
        GLOB
        a7x_utils_files
        tstUtil/tst_sm_util.c
        libCommon/infra/sm_app_boot.c
        libCommon/infra/app_boot_nfc.c
    )

    IF(WithHostCrypto_MBEDTLS)
        LIST(
            APPEND
            a7x_utils_files
            tstUtil/tstHostCrypto_mbedtls.c
            tstUtil/tstHostCrypto_mbedtls_aes.c
            tstUtil/hkdf_mbedtls.c
        )
    ENDIF()

    IF(WithHostCrypto_OPENSSL)
        LIST(
            APPEND
            a7x_utils_files
            tstUtil/tstHostCrypto.c
            tstUtil/hkdf.c
        )
    ENDIF()

    IF(WithKSDK)
        LIST(
            APPEND
            a7x_utils_files
            libCommon/infra/sm_demo_utils.c
            libCommon/infra/sm_app_boot.c
        )
    ENDIF()

    IF(WithRTOS_FreeRTOS AND WithKSDK)
        LIST(
            APPEND
            a7x_utils_files
            libCommon/infra/sm_demo_utils_rtos.c
        )
    ENDIF()

    ADD_LIBRARY(a7x_utils ${a7ch_cl_util_file} ${a7x_utils_files})

    TARGET_INCLUDE_DIRECTORIES(
        a7x_utils
        PUBLIC tstUtil
        PUBLIC api/inc
        PUBLIC platform/ksdk
        PUBLIC libCommon/scp
        PUBLIC a71ch/inc
        PUBLIC libCommon/hostCrypto
               #PRIVATE ${SIMW_TOP_DIR}/ext/amazon-freertos/lib/third_party/jsmn
    )

    IF(WithApplet_A71CH OR WithApplet_A71CH_SIM)
        TARGET_LINK_LIBRARIES(a7x_utils a71ch)
    ENDIF()
    IF(WithApplet_A71CL OR WithApplet_SE050_L)
        TARGET_LINK_LIBRARIES(a7x_utils smCom)
    ENDIF()
    TARGET_LINK_LIBRARIES(a7x_utils smCom)

    # UWB MW does not have board,
    # Only P&T MW has it.
    IF (NOT (UWBIOT_OS_FREERTOS OR UWBIOT_OS_NATIVE))
        IF(WithKSDK)
            TARGET_LINK_LIBRARIES(a7x_utils board)
        ENDIF()
    ENDIF()

    IF(WithRTOS_FreeRTOS)
        TARGET_LINK_LIBRARIES(
            a7x_utils
            freertos-kernel
        )
    ENDIF()

    IF(ENABLE_CLOUD_DEMOS)
        TARGET_LINK_LIBRARIES(
            a7x_utils
            freertos-ip
        )
    ENDIF()

    IF(WithHost_PCWindows OR WithHost_LinuxLike)
        TARGET_COMPILE_DEFINITIONS(a7x_utils PUBLIC AX_CONSOLE_LOG)
    ENDIF()
ENDIF()

IF(WithApplet_LoopBack OR WithApplet_SE05X)
    PROJECT(a7x_utils)
    SET(HAVE_A7X_UTILS ON)

    FILE(
        GLOB
        a7x_utils_files
        libCommon/infra/sm_app_boot.c
        libCommon/infra/app_boot_nfc.c
        libCommon/infra/sm_connect.*
        libCommon/infra/global_platf.*
        libCommon/infra/cm_commands.*
        libCommon/scp/scp.*
    )

    IF(WithKSDK)
        LIST(
            APPEND
            a7x_utils_files
            libCommon/infra/sm_demo_utils.c
            libCommon/infra/sm_app_boot.c
        )
    ENDIF()

    IF(WithRTOS_FreeRTOS AND WithKSDK)
        LIST(
            APPEND
            a7x_utils_files
            libCommon/infra/sm_demo_utils_rtos.c
        )
    ENDIF()

    IF(WithHost_Android)
        ADD_LIBRARY(a7x_utils SHARED ${a7x_utils_files})
    ELSE()
        ADD_LIBRARY(a7x_utils ${a7x_utils_files})
    ENDIF()

    TARGET_INCLUDE_DIRECTORIES(
        a7x_utils
        PUBLIC tstUtil
        PUBLIC api/inc
        PUBLIC libCommon/scp
        PUBLIC a71ch/inc
        PUBLIC platform/ksdk
        PUBLIC ${SIMW_TOP_DIR}/sss/inc
               #PRIVATE ${SIMW_TOP_DIR}/ext/amazon-freertos/lib/third_party/jsmn
    )

    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        STREQUAL
        "GNU"
    )
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-stringop-overflow
    )
    ENDIF()

    TARGET_LINK_LIBRARIES(a7x_utils smCom)

    IF(WithRTOS_FreeRTOS)
        TARGET_LINK_LIBRARIES(
            a7x_utils
            freertos-kernel
        )
    ENDIF()

    IF(ENABLE_CLOUD_DEMOS)
        TARGET_LINK_LIBRARIES(
            a7x_utils
            freertos-ip
        )
    ENDIF()

    IF(WithHostCrypto_MBEDCRYPTO)
        TARGET_LINK_LIBRARIES(a7x_utils mbedtls)
        TARGET_COMPILE_DEFINITIONS(a7x_utils PUBLIC MBEDCRYPTO)
    ELSEIF(WithHostCrypto_MBEDTLS)
        TARGET_LINK_LIBRARIES(a7x_utils mbedtls)
        TARGET_COMPILE_DEFINITIONS(a7x_utils PUBLIC MBEDTLS)
    ENDIF()

ENDIF()

IF (WithApplet_SE051_UWB)
    ADD_SUBDIRECTORY(fira)
ENDIF()

IF(
    WithKSDK
    AND WithRTOS_Default
    AND (NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS)
)
    IF(
        WithSMCOM_SCI2C
        OR WithSMCOM_T1oI2C
        OR WithSMCOM_T1oI2C_GP1_0
    )
        IF(NXPProprietary)
            ADD_SUBDIRECTORY(vcom/ksdk)
            IF(WithHost_frdmk64f)
                IF(WithApplet_A71CH OR WithApplet_SE05X)
                    ADD_SUBDIRECTORY(ccid/ksdk)
                ENDIF()
            ENDIF()
        ENDIF()
    ENDIF()
ENDIF()

IF(WithHostCrypto_OPENSSL)
    IF(WithApplet_A71CH OR WithApplet_A71CH_SIM)
        # MESSAGE(STATUS "Request for OpenSSL Engine")
        ADD_SUBDIRECTORY(embSeEngine)
    ENDIF()
ENDIF()

IF(WithHost_LinuxLike AND HAVE_A7X_UTILS)
    INSTALL(TARGETS a7x_utils DESTINATION lib)
    INSTALL(
        DIRECTORY inc/
        DESTINATION ${SIMW_INSTALL_INC_DIR}
        FILES_MATCHING
        PATTERN "*.h"
    )
ENDIF()
