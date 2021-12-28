#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

PROJECT(a71ch_engine_legacy)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    src/ax_a71chEngine.c
    src/ax_cryptoIpc.c
)

ADD_LIBRARY(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_files})

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    a71ch
    a7x_utils
    SSS_APIs
)

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${OPENSSL_LIBRARIES})

TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC inc)

CREATE_BINARY(${PROJECT_NAME})

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${SIMW_TOP_DIR}/hostlib/hostLib/embSeEngine/bin
    COMMENT "Copy dll to ${SIMW_TOP_DIR}/hostlib/hostLib/embSeEngine/bin"
)
