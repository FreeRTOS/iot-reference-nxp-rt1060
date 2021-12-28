PROJECT(mwlog)

FILE(
    GLOB
    source_files
    *.h
)

IF(WithHost_Android)
    FILE(
        GLOB
        nxLog_sources
        nxLog_Android.c
    )
ELSEIF(NOT WithLog_SeggerRTT)
    IF(NOT WithHost_lpcxpresso55s_ns)
        FILE(
            GLOB
            nxLog_sources
            nxLog.c
        )
    ENDIF()
    IF(WithHost_lpcxpresso55s_ns)
        FILE(
            GLOB
            nxLog_sources
            nxLog_lpc55s_ns.c
        )
    ENDIF()
ENDIF()

IF(BUILD_SHARED_LIBS)
    ADD_LIBRARY(
        ${PROJECT_NAME}
        SHARED
        ${source_files}
        ${nxLog_sources}
    )
ELSE()
    ADD_LIBRARY(
        ${PROJECT_NAME}
        ${source_files}
        ${nxLog_sources}
    )
ENDIF()

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PUBLIC .
    PUBLIC ../../platform/inc
    PUBLIC ../infra
)

IF(WithHost_lpcxpresso55s_ns)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} lpc55s_veneer)
ENDIF()


# UWB MW does not have board,
# Only P&T MW has it.
IF (NOT (UWBIOT_OS_FREERTOS OR UWBIOT_OS_NATIVE))
    IF(WithKSDK)
        TARGET_LINK_LIBRARIES(${PROJECT_NAME} board)
    ENDIF()
ENDIF()

IF(WithRTOS_FreeRTOS)
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} freertos-kernel)
ENDIF()

IF(CMAKE_COMPILER_IS_GNUCC AND (NOT WithKSDK))
    TARGET_LINK_LIBRARIES(${PROJECT_NAME} -lpthread)
ENDIF()

IF(WithHost_LinuxLike)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()
