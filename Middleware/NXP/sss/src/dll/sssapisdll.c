/* Copyright 2018,2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fsl_sss_api.h>
#include <fsl_sss_se05x_types.h>
#include <stdio.h>

//#if defined(__GNUC__)
//static const void * keep_symbols[] __attribute__((used)) = {
//  &Se05x_API_DeleteAll_Iterative,
//  NULL,
//};
//#endif

#ifdef _WIN32

#include <windows.h>

BOOL APIENTRY DllMain(HANDLE hModule, // Handle to DLL module
    DWORD ul_reason_for_call,
    LPVOID lpReserved) // Reserved
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // A process is loading the DLL.
        break;

    case DLL_THREAD_ATTACH:
        // A process is creating a new thread.
        break;

    case DLL_THREAD_DETACH:
        // A thread exits normally.
        break;

    case DLL_PROCESS_DETACH:
        // A process unloads the DLL.
        break;
    }
    return TRUE;
}

#endif /* _WIN32 */
