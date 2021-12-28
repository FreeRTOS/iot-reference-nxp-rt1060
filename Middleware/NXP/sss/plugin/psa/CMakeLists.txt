# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(PSA_ALT)

IF(WithHost_lpcxpresso55s_s)
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/psa_alt.c
        src/psa_alt_utils.c
        src/sss_psa_alt.c
        src/secure/psa_secure.c
        src/secure/psa_alt_deserialize.c
        src/secure/psa_alt_se_driver.c
        src/psa_alt_flash.c
    )

ELSEIF(WithHost_lpcxpresso55s_ns)
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/nonsecure/psa_alt_serialize.c
    )

ELSEIF(WithHost_lpcxpresso55s)
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/psa_alt.c
        src/psa_alt_utils.c
        src/sss_psa_alt.c
        src/psa_alt_flash.c
    )

ELSE()
    FILE(
        GLOB
        ${PROJECT_NAME}_files
        src/psa_alt.c
        src/psa_alt_utils.c
        src/sss_psa_alt.c
    )

ENDIF()

IF(WithHost_lpcxpresso55s_s)
    ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${${PROJECT_NAME}_files})
ENDIF()

IF(WithHost_PCWindows)
    # FIXME: Only required for testing
    ADD_DEFINITIONS(-DEX_SSS_BOOT_DO_ERASE=1)
ENDIF()

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

IF(WithApplet_SE05X)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} se05x)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a7x_utils)
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
    PRIVATE ${SIMW_TOP_DIR}/ext/mbed-crypto/include
    PUBLIC inc
)

IF(WithHost_lpcxpresso55s_s)
    CREATE_BINARY(${PROJECT_NAME})
ENDIF()

#### PROJECT(psa_interface)
#### ADD_LIBRARY(psa_interface INTERFACE)
####
#### TARGET_INCLUDE_DIRECTORIES(psa_interface INTERFACE inc)
