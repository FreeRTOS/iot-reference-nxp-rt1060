#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(a71ch_Main)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    *.c
    *.h
)

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} a7x_utils)

IF(
    CMAKE_CXX_COMPILER
    MATCHES
    ".*clang"
    OR CMAKE_CXX_COMPILER_ID
       STREQUAL
       "AppleClang"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-sign-compare
        PRIVATE -Wno-unknown-attributes
        PRIVATE -Wno-format
    )
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(
        ${PROJECT_NAME}
        PRIVATE -Wno-error=format
        PRIVATE -Wno-format
        PRIVATE -Wno-stringop-overflow
        PRIVATE -Wno-format-security
    )
ENDIF()

CREATE_BINARY(${PROJECT_NAME})
