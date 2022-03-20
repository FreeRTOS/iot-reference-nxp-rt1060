#ifndef _UNITY_CONFIG_H
#define _UNITY_CONFIG_H

#include "fsl_debug_console.h"

#define UNITY_OUTPUT_CHAR(a)    DbgConsole_Putchar(a)
#define UNITY_OUTPUT_START()    DbgConsole_Printf("-----TESTS START-----\r\n")
#define UNITY_OUTPUT_FLUSH()    DbgConsole_Flush()
#define UNITY_OUTPUT_COMPLETE() DbgConsole_Printf("-----TESTS COMPLETE-----\r\n")

#endif
