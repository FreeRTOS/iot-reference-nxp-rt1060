# Copyright 2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(ex_ecdaa)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    *.c
    *.h
)

ADD_EXECUTABLE(${PROJECT_NAME} ${KSDK_STARTUP_FILE} ${${PROJECT_NAME}_files})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ex_common)

CREATE_BINARY(${PROJECT_NAME})
