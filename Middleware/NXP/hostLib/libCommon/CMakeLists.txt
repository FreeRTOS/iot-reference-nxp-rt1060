#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# Common and Communication Layers

IF(WithHost_Win10IoT)
    PROJECT(smComWin10IoTWrapper)
    FILE(
        GLOB
        smCom_Win10IoT_wrapper
        ../platform/win10iot/i2c_wrapper.cpp
        ../platform/win10iot/i2c_wrapper.h
        ../platform/inc/i2c_a7.h
    )
    ADD_LIBRARY(${PROJECT_NAME} ${smCom_Win10IoT_wrapper})

    SET_PROPERTY(TARGET ${PROJECT_NAME} PROPERTY VS_WINRT_COMPONENT TRUE)
ENDIF()

PROJECT(smCom)

IF(WithHost_PCWindows)
    IF(WithSMCOM_VCOM)
        FILE(
            GLOB
            smCom_vcom_sources
            smCom/smComSerial*.h
            smCom/smComSerial_win32.c
        )
    ENDIF()
    IF(WithSMCOM_JRCP_V1 OR WithSMCOM_JRCP_V1_AM)
        FILE(
            GLOB
            smCom_socket_sources
            smCom/smComSocket*.h
            smCom/smComSocket_win32.c
        )
    ENDIF()
ENDIF()
IF(WithSMCOM_PCSC)
    FILE(
        GLOB
        smCom_pcsc_sources
        smCom/smComPCSC.c
        smCom/smComPCSC.h
    )
ENDIF()

IF(WithSMCOM_JRCP_V2)
    FILE(
        GLOB
        smCom_jrcp_sources
        smCom/smComJRCP*.h
        smCom/smComJRCP*.c
    )
ENDIF()

IF(WithSMCOM_JRCP_V1 OR WithSMCOM_JRCP_V1_AM)
    FILE(
        GLOB
        smCom_socket_sources
        smCom/smComSocket*.h
    )
    IF(WithHost_PCWindows)
        LIST(
            APPEND
            smCom_socket_sources
            smCom/smComSocket_win32.c
        )
    ELSE()
        LIST(
            APPEND
            smCom_socket_sources
            smCom/smComSocket_linux.c
            smCom/smComSocket_fd.c
        )
    ENDIF()
ENDIF()

IF(WithHost_Darwin)
    IF(WithSMCOM_VCOM)
        FILE(
            GLOB
            smCom_vcom_sources
            smCom/smComSerial*.h
            smCom/smComSerial_Darwin.c
            smCom/smComSocket_fd.c
        )
    ENDIF()
ENDIF()

IF(WithHost_PCLinux)
    IF(WithSMCOM_VCOM)
        FILE(
            GLOB
            smCom_vcom_sources
            smCom/smComSerial*.h
            smCom/smComSerial_PCLinux.c
            smCom/smComSocket_fd.c
        )
    ENDIF()
ENDIF()

IF(WithSMCOM_SCI2C)
    FILE(
        GLOB
        smCom_sci2c_sources
        smCom/sci2c*.h
        smCom/sci2c*.c
        smCom/smComSCI2C*.c
    )
ENDIF()

IF(WithHost_iMXLinux)
    FILE(
        GLOB
        smCom_imx_sources
        ../platform/linux/i2c_a7.c
        ../platform/imx/se05x_reset.c
    )
ENDIF()

IF(WithHost_Win10IoT)
    FILE(
        GLOB
        smCom_Win10IoT_sources
        ../platform/win10iot/i2c_a7.c
    )

ENDIF()

IF(WithHost_Raspbian)
    FILE(
        GLOB
        smCom_raspbian_sources
        ../platform/linux/i2c_a7.c
        ../platform/rsp/se05x_reset.c
    )
ENDIF()

IF(WithHost_Android)
    FILE(
        GLOB
        smCom_android_sources
        ../platform/linux/i2c_a7.c
        ../platform/imx/se05x_reset.c
    )
ENDIF()

IF(WithSMCOM_T1oI2C)
    FILE(
        GLOB
        smCom_T1oi2c_sources
        smCom/T1oI2C/*.c
        smCom/smComT1oI2C*.h
        smCom/smComT1oI2C*.c
    )
ENDIF()

IF(WithSMCOM_T1oI2C_GP1_0)
    FILE(
        GLOB
        smCom_T1oI2C_GP1_0_sources
        smCom/T1oI2C/*.c
        smCom/smComT1oI2C*.h
        smCom/smComT1oI2C*.c
    )
ENDIF()

IF(WithSMCOM_PN7150)
    FILE(
        GLOB
        smCom_pn7150_sources
        smCom/smComPN7150*.h
        smCom/smComPN7150*.c
    )
ENDIF()

IF(WithSMCOM_Thread)
    FILE(
        GLOB
        smCom_thread_sources
        smCom/smComThread*.h
        smCom/smComThread*.c
    )
ENDIF()

IF(WithSMCOM_RC663_VCOM OR WithSMCOM_RC663_SPI)
    FILE(
        GLOB
        smCom_rc663_sources
        smCom/smComNxpNfcRdLib*.h
        smCom/smComNxpNfcRdLib*.c
        smCom/npRdLib/*.c
        smCom/npRdLib/*.h
    )
ENDIF()

IF(WithKSDK)
    SET(smCom_timer_sources ../platform/ksdk/timer_kinetis.c ../tstUtil/tst_sm_time_kinetis.c)
ELSE()
    SET(smCom_timer_sources ../platform/generic/sm_timer.c ../tstUtil/tst_sm_time.c)
ENDIF()

FILE(
    GLOB
    smCom_sources
    infra/sm_apdu.*
    infra/sm_errors.*
    infra/sm_printf.c
    smCom/smCom.*
    ${smCom_vcom_sources}
    ${smCom_jrcp_sources}
    ${smCom_socket_sources}
    ${smCom_sci2c_sources}
    ${smCom_timer_sources}
    ${smCom_T1oi2c_sources}
    ${smCom_T1oI2C_GP1_0_sources}
    ${smCom_imx_sources}
    ${smCom_Win10IoT_sources}
    ${smCom_raspbian_sources}
    ${smCom_android_sources}
    ${smCom_pn7150_sources}
    ${smCom_thread_sources}
    ${smCom_pcsc_sources}
    ${smCom_rc663_sources}
)

IF(WithSCP_SCP03_SSS)
    FILE(
        GLOB
        nxScp_files
        nxScp/*.c
        ../inc/nxScp03_*.h
    )
ENDIF()

ADD_LIBRARY(
    smCom
    ${smCom_sources}
    ${nxScp_files}
)

TARGET_COMPILE_DEFINITIONS(smCom PRIVATE # FLOW_VERBOSE
)

TARGET_INCLUDE_DIRECTORIES(
    smCom
    PUBLIC smCom
    PUBLIC infra
    PUBLIC ../inc
    PUBLIC ../platform/inc
    PUBLIC ../tstUtil
    PUBLIC ../accessManager/inc
    PUBLIC log
    PRIVATE ${SIMW_TOP_DIR}/sss/ex/inc
)

IF(WithSCP_SCP03_SSS)
    INCLUDE_DIRECTORIES(${SIMW_TOP_DIR}/sss/inc)
    IF(WithKSDK)
        INCLUDE_DIRECTORIES(${SIMW_TOP_DIR}/sss/port/kinetis)
    ELSE()
        INCLUDE_DIRECTORIES(${SIMW_TOP_DIR}/sss/port/x86 #TODO Purnank to fix1
        )
    ENDIF()
ELSE()
    TARGET_INCLUDE_DIRECTORIES(smCom PRIVATE scp)
ENDIF()

IF(WithSMCOM_T1oI2C)
    TARGET_INCLUDE_DIRECTORIES(smCom PUBLIC smCom/T1oI2C)
ENDIF()

IF(WithSMCOM_T1oI2C_GP1_0)
    TARGET_INCLUDE_DIRECTORIES(smCom PUBLIC smCom/T1oI2C)
ENDIF()

IF(NOT WithLog_SeggerRTT)
    TARGET_LINK_LIBRARIES(smCom mwlog)
ENDIF()
TARGET_INCLUDE_DIRECTORIES(smCom PUBLIC log)

IF(WithSMCOM_JRCP_V2)
    TARGET_LINK_LIBRARIES(smCom jrcplib)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SMCOM_JRCP_V2 # New version
    )
ENDIF()

IF(WithSMCOM_PN7150)
    TARGET_LINK_LIBRARIES(smCom PN7150Nfc)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SMCOM_PN7150)
ENDIF()

IF(WithSMCOM_JRCP_V1 OR WithSMCOM_JRCP_V1_AM)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SMCOM_JRCP_V1 # Old version
    )
ENDIF()

IF(WithSMCOM_JRCP_V1_AM)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SMCOM_JRCP_V1_AM)
ENDIF()

IF(WithSMCOM_PCSC)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SMCOM_PCSC)
    IF(WithHost_PCLinux)
        TARGET_INCLUDE_DIRECTORIES(smCom PRIVATE /usr/include/PCSC)
    ENDIF()
ENDIF()

IF(WithSMCOM_VCOM)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC RJCT_VCOM)
ENDIF()

IF(WithSMCOM_SCI2C)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SCI2C)
ENDIF()

IF(WithSMCOM_T1oI2C)
    TARGET_COMPILE_DEFINITIONS(smCom PRIVATE T1oI2C_UM11225)
ENDIF()

IF(WithSMCOM_T1oI2C_GP1_0)
    TARGET_COMPILE_DEFINITIONS(smCom PRIVATE T1oI2C_GP1_0)
ENDIF()

IF(WithSMCOM_Thread)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SMCOM_THREAD)
ENDIF()

IF(WithSMCOM_RC663_VCOM)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC SMCOM_RC663_VCOM)
    TARGET_LINK_LIBRARIES(smCom nxpnfcrdlib)
ENDIF()


# UWB MW does not have board,
# Only P&T MW has it.
IF (NOT (UWBIOT_OS_FREERTOS OR UWBIOT_OS_NATIVE))
    IF(WithKSDK)
        TARGET_LINK_LIBRARIES(smCom board)
    ENDIF()
ENDIF()

IF(WithHostCrypto_MBEDTLS OR WithHostCrypto_MBEDCRYPTO)
    TARGET_LINK_LIBRARIES(smCom mbedtls)
ENDIF()

IF(WithApplet_A71CH OR WithApplet_A71CH_SIM)
    TARGET_COMPILE_DEFINITIONS(
        smCom PUBLIC TGT_A71CH
                     # FLOW_VERBOSE
    )
ENDIF()

IF(WithApplet_LoopBack)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC TGT_NONE)
ENDIF()

IF(WithApplet_A71CL OR WithApplet_SE050_L)
    TARGET_COMPILE_DEFINITIONS(
        smCom PUBLIC TGT_A71CL TGT_A71ID2
                     # FLOW_VERBOSE
    )
ENDIF()

IF(WithHost_iMXLinux)
    TARGET_COMPILE_DEFINITIONS(smCom PUBLIC PLATFORM_IMX)
ENDIF()

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${OPENSSL_LIBRARIES})

IF(WithLog_SeggerRTT)
    TARGET_LINK_LIBRARIES(smCom seggerrtt)
ENDIF()

IF(WithHost_lpcxpresso55s_ns)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} lpc55s_veneer)
ENDIF()

IF(WithHost_Raspbian)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} pthread)
ENDIF()

IF(WithHost_Android)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} log)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()

IF(WithHost_LinuxLike)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
    INSTALL(
        DIRECTORY infra/ smCom/
        DESTINATION ${SIMW_INSTALL_INC_DIR}
        FILES_MATCHING
        PATTERN "*.h"
    )
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCC AND (NOT WithKSDK))
    TARGET_LINK_LIBRARIES(smCom -lpthread)
ENDIF()

IF(WithHost_PCLinux)
    TARGET_LINK_LIBRARIES(smCom -lrt)
ENDIF()

IF(WithHost_Win10IoT)
    SET_TARGET_PROPERTIES(smCom PROPERTIES LINK_FLAGS_RELEASE "/defaultlib:vccorlib.lib /defaultlib:msvcrt.lib")
    SET_TARGET_PROPERTIES(smCom PROPERTIES LINK_FLAGS_DEBUG "/defaultlib:vccorlibd.lib /defaultlib:msvcrtd.lib")

    TARGET_LINK_LIBRARIES(${PROJECT_NAME} smComWin10IoTWrapper)
ENDIF()

IF(WithSMCOM_PCSC)
    IF(WithHost_PCWindows)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} Winscard)
    ENDIF()
    IF(WithHost_Darwin)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} "-framework PCSC")
    ENDIF()
    IF(WithHost_PCLinux)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} pcsclite)
    ENDIF()
ENDIF()

IF(WithRTOS_FreeRTOS AND WithHost_PCWindows)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-kernel)
ENDIF()