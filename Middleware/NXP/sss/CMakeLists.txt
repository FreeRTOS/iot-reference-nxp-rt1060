#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(SSS_APIs LANGUAGES C)

FILE(
    GLOB
    API_FILES
    inc/*.h
    inc/*.h.in
    inc/*.hpp
    src/*.c
    src/sscp/fsl_sss_sscp.c
    src/a71ch/*.c
    src/a71cl/*.c
    src/user/*.c
    src/user/crypto/aes.c
    src/user/crypto/aes_cmac.c
    src/user/crypto/aes_cmac_multistep.c
    src/user/crypto/*.h
    src/se050/*.c
    src/se05x/*.c
    src/mbedtls/*.c
    src/mbedtls/*.cpp
    src/openssl/*.c
    src/keystore/*.c
    src/a71cx_common/*.c
    src/lpc55s/*.c
    port/default/*.h
    ../doc/input/doc_*.h
    cpp/*.cpp
    ${PlugAndTrustMW_BINARY_DIR}/fsl_sss_ftr.h
)

IF(WithHost_Android)
    ADD_LIBRARY(${PROJECT_NAME} SHARED ${API_FILES})
ELSE()
    ADD_LIBRARY(${PROJECT_NAME} ${API_FILES})
ENDIF()

TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC inc)

IF(WithKSDK)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC port/ksdk)
ELSE()
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC port/default)
ENDIF()

IF(WithHostCrypto_MBEDTLS OR WithHostCrypto_MBEDCRYPTO)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls)
ENDIF()

IF(WithHostCrypto_OPENSSL)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
ENDIF()

IF(WithHostCrypto_User)
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC user/crypto)
ENDIF()

IF(WithApplet_A71CH OR WithApplet_A71CH_SIM)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a71ch)
ENDIF()

IF(WithApplet_A71CL OR WithApplet_SE050_EAR_CL)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} a71cl)
ENDIF()

IF(WithApplet_SE05X)
    TARGET_LINK_LIBRARIES(
        ${PROJECT_NAME}
        se05x
        a7x_utils
    )
ENDIF()

TARGET_LINK_LIBRARIES(${PROJECT_NAME} smCom)

IF(WithHost_LinuxLike)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

IF(WithRTOS_Default AND NXPInternal)
    IF(WithLargePrograms AND (NOT SSS_HAVE_HOST_LPCXPRESSO55S_NS))
        ADD_SUBDIRECTORY(tst)
    ELSE()
        ADD_SUBDIRECTORY(tst/src)
    ENDIF()
ENDIF()

IF(WithKSDK AND WithRTOS_FreeRTOS AND NXPInternal)
    ADD_SUBDIRECTORY(tst/src)
ENDIF()

IF(WithLargePrograms)
    ADD_SUBDIRECTORY(ex)
ELSE()
    ADD_SUBDIRECTORY(ex/src)
ENDIF()

IF(SSS_HAVE_HOSTCRYPTO_ANY)
    IF(
        WithApplet_A71CH
        OR WithApplet_A71CH_SIM
        OR WithApplet_SE05X
    )
        IF(
            WithHost_PCWindows
            OR WithHost_Darwin
            OR WithHost_LinuxLike
        )
            # ADD_SUBDIRECTORY(src/dll)
            PROJECT(sssapisw)
            IF(MSVC)
                IF(WithApplet_A71CH OR WithApplet_A71CH_SIM)
                    SET(def_file "src/dll/sssapisdll_a71ch.def")
                ENDIF()
                IF(WithApplet_SE05X)
                    SET(def_file "src/dll/sssapisdll_se05x.def")
                ENDIF()
            ENDIF()
            ADD_LIBRARY(
                sssapisw SHARED
                ${API_FILES}
                ${def_file}
                src/dll/sssapisdll.c
            )
            TARGET_LINK_LIBRARIES(sssapisw SSS_APIs)
            ADD_CUSTOM_COMMAND(
                TARGET sssapisw
                POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:sssapisw> ${SIMW_TOP_DIR}/tools
                COMMENT "Copy dll to ${SIMW_TOP_DIR}/tools"
            )
        ENDIF()
    ELSEIF(
        WithDllSupport
        AND WithHost_PCWindows
        AND MSVC
    )
        # ADD_SUBDIRECTORY(src/dll)
        PROJECT(sssapisw)
        SET(def_file "src/dll/sssapisdll.def")
        ADD_LIBRARY(
            sssapisw SHARED
            ${API_FILES}
            ${def_file}
            src/dll/sssapisdll.c
        )
        TARGET_LINK_LIBRARIES(sssapisw SSS_APIs)
        ADD_CUSTOM_COMMAND(
            TARGET sssapisw
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:sssapisw> ${SIMW_TOP_DIR}/tools
            COMMENT "Copy dll to ${SIMW_TOP_DIR}/tools"
        )
    ENDIF()

    IF(WithHostCrypto_OPENSSL)
        IF(
            WithApplet_A71CH
            OR WithApplet_A71CH_SIM
            OR WithApplet_SE05X
            OR WithHostCrypto_MBEDTLS
        )
            ADD_SUBDIRECTORY(plugin/openssl)
        ENDIF()
    ENDIF()

    IF(WithHostCrypto_MBEDCRYPTO)
        IF(WithApplet_SE05X)
            ADD_SUBDIRECTORY(plugin/psa)
        ENDIF()
    ENDIF()

    IF(WithHost_LinuxLike)
        INSTALL(
            DIRECTORY inc/ port/default/
            DESTINATION ${SIMW_INSTALL_INC_DIR}
            FILES_MATCHING
            PATTERN "*.h"
        )
    ENDIF()

    IF(WithHost_LinuxLike)
        INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
    ENDIF(WithHost_LinuxLike)
ENDIF(SSS_HAVE_HOSTCRYPTO_ANY)
