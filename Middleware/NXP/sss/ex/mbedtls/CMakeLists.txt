#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

MACRO(
    SSS_MBEDTLS_CLIENT_PROJECT
    prj_prefix
    prj_name
)

    PROJECT(mbedtls_ex_${prj_prefix}_${prj_name}_client)

    FILE(
        GLOB
        ${prj_name}_files
        ex_sss_${prj_name}.c
        ../../plugin/mbedtls/sss_mbedtls.c
        ../../plugin/mbedtls/sss_mbedtls_rsa.c
        *.h
    )
    IF(WithApplet_A71CH OR WithApplet_A71CH_SIM)
        FILE(
            GLOB
            ax_files
            ../../../hostlib/hostLib/libCommon/infra/sm_app_boot.c
        )
    ENDIF()
    IF(WithApplet_SE05X)
        FILE(
            GLOB
            ax_files
            ../../../hostlib/hostLib/libCommon/infra/sm_app_boot.c
        )
    ENDIF()

    ADD_DEFINITIONS("-DMBEDTLS_CONFIG_FILE=\"sss_mbedtls_x86_config.h\"")

    ADD_EXECUTABLE(
        ${PROJECT_NAME}
        ${KSDK_STARTUP_FILE}
        ${ax_files}
        ${${prj_name}_files}
    )

    TARGET_INCLUDE_DIRECTORIES(
        ${PROJECT_NAME}
        PRIVATE
            ../inc
            ../../plugin/mbedtls
            ../../../hostlib/useCase/common
    )

    TARGET_LINK_LIBRARIES(${PROJECT_NAME} ex_common)
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/tools
        COMMENT "Copy exe to ${SIMW_TOP_DIR}/tools"
    )

    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        MATCHES
        "MSVC"
    )
        IF(NXPInternal)
            TARGET_COMPILE_OPTIONS(
                ${PROJECT_NAME} PRIVATE /wd4127 # conditional expression is constant
            )
        ENDIF()
    ENDIF()

    CREATE_BINARY(${PROJECT_NAME})
ENDMACRO()

MACRO(
    ORIGINAL_MBEDTLS_PRJECT
    file_name
    prj_name
)

    PROJECT(mbedtls_ex_orig_${prj_name})

    ADD_DEFINITIONS("-DMBEDTLS_CONFIG_FILE=\"sss_mbedtls_x86_config.h\"")

    ADD_EXECUTABLE(
        ${PROJECT_NAME} ${SIMW_TOP_DIR}/ext/mbedtls/${file_name}
                        ${SIMW_TOP_DIR}/ext/mbedtls/programs/ssl/query_config.c
    )

IF(WithKSDK)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls)
ELSE() # KSDK
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls smCom SSS_APIs)
ENDIF()

    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/tools
        COMMENT "Copy exe to ${SIMW_TOP_DIR}/tools"
    )

    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        MATCHES
        "MSVC"
    )
        IF(NXPInternal)
            TARGET_COMPILE_OPTIONS(
                ${PROJECT_NAME} PRIVATE /wd4127 # conditional expression is constant
            )
        ENDIF()
    ENDIF()

    CREATE_BINARY(${PROJECT_NAME})
ENDMACRO()

SSS_MBEDTLS_CLIENT_PROJECT(sss ssl2)
ORIGINAL_MBEDTLS_PRJECT(programs/ssl/ssl_server2.c ssl_server2)
SSS_MBEDTLS_CLIENT_PROJECT(sss dtls)
#SSS_MBEDTLS_CLIENT_PROJECT(ssl2_provisioning)

# DTLS SERVER #################
PROJECT(mbedtls_ex_orig_dtls_server)

ADD_DEFINITIONS("-DMBEDTLS_CONFIG_FILE=\"sss_mbedtls_x86_config.h\"")

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} dtls_server.c)

IF(WithKSDK)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls)
ELSE() # KSDK
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} mbedtls smCom SSS_APIs)
ENDIF()

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/tools
    COMMENT "Copy exe to ${SIMW_TOP_DIR}/tools"
)

CREATE_BINARY(${PROJECT_NAME})
# DTLS SERVER #################
