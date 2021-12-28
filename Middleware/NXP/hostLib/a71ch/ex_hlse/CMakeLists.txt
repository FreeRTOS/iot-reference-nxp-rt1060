PROJECT(ex_A71CHHLSEMain)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    *.c
    ../../tstUtil/tst_hlse_a71ch_util.c
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
        PRIVATE -Wno-unused-function
    )
ENDIF()

IF(
    "${CMAKE_CXX_COMPILER_ID}"
    STREQUAL
    "GNU"
)
    TARGET_COMPILE_OPTIONS(${PROJECT_NAME}
    PRIVATE -Wno-format
    PRIVATE -Wno-format-security
    )
ENDIF()

CREATE_BINARY(${PROJECT_NAME})
