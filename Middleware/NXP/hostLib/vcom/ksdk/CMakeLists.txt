# Copyright 2019,2020 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

PROJECT(vcom)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    *.c
    *.h
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/class/cdc/*.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/osa/usb_osa_bm.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/class/usb_device_cdc_acm.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/class/usb_device_class.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/usb_device_ch9.c
    ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/usb_device_dci.c
)

IF(WithHost_frdmk64f)
    FILE(
        GLOB
        frdmk64f_files
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/usb_device_khci.c
    )
ENDIF()

IF(WithHost_evkmimxrt1060)
    FILE(
        GLOB
        evkmimxrt1060_files
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/usb_device_ehci.c
        # ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/usb_device_lpcip3511.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/phy/usb_phy.c
    )
ENDIF()

IF(
    WithHost_lpcxpresso55s
    OR WithHost_lpcxpresso55s_s
    OR WithHost_lpcxpresso55s_ns
)
    FILE(
        GLOB
        lpcxpresso55s_files
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/usb_device_ehci.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/usb_device_lpcip3511.c
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/phy/usb_phy.c
    )
ENDIF()

ADD_EXECUTABLE(
    ${PROJECT_NAME}
    ${KSDK_STARTUP_FILE}
    ${${PROJECT_NAME}_files}
    ${frdmk64f_files}
    ${evkmimxrt1060_files}
    ${lpcxpresso55s_files}
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    a7x_utils
    smCom
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE
        .
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/device/class
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/include
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/osa
        ${SIMW_TOP_DIR}/ext/mcu-sdk/middleware/usb/phy
        ${SIMW_TOP_DIR}/ext/mcu-sdk/devices/${KSDK_CPUName}/usb_vcom
)

TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PRIVATE USB_STACK_BM)

CREATE_BINARY(${PROJECT_NAME})
IF(
    CMAKE_BUILD_TYPE
    STREQUAL
    "Release"
)
    COPY_TO_SOURCEDIR_RENAME(
        ${PROJECT_NAME}
        ${eSEName}_${PROJECT_NAME}
        binaries/MCU/${eSEName}
        ${SMCOM}
    )
ENDIF()
