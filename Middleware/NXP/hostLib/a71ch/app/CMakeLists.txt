#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(A71CHConfigTool)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    *.c
    *.h
    ../../tstUtil/axCliUtil.c
    ../../tstUtil/axEccRefPem.c
)

FILE(
    GLOB
    imx_files
    configCliInteractive_ln.c
)

LIST(
    REMOVE_ITEM
    ${PROJECT_NAME}_files
    ${imx_files}
)

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} a7x_utils SSS_APIs)

CREATE_BINARY(${PROJECT_NAME})

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/hostlib/hostLib/embSeEngine/bin
    COMMENT "Copy config tool exe to ${SIMW_TOP_DIR}/hostlib/hostLib/embSeEngine/bin"
)

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    MATCHES
    "MSVC"
)
    IF(NXPInternal)
        TARGET_COMPILE_OPTIONS(
            ${PROJECT_NAME}
            PRIVATE /wd4267 # '=': conversion from 'size_t' to 'int', possible loss of data
            PRIVATE /wd4701 #  potentially uninitialized local variable used
        )
    ENDIF()
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(${PROJECT_NAME}
    PRIVATE -Wno-stringop-overflow
    )
ENDIF()

IF(WithHost_LinuxLike)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
ENDIF()
