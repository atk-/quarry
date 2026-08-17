/*
 * dllmain.c — Entry point for the Quarry hook DLL.
 *
 * On DLL_PROCESS_ATTACH:
 *   1. Connect to the Quarry named pipe server (IPC init).
 *   2. Install inline hooks on key APIs.
 *
 * On DLL_PROCESS_DETACH:
 *   1. Remove all hooks (restore original bytes).
 *   2. Close the IPC pipe.
 *
 * DLL_THREAD_ATTACH / DETACH are disabled (DisableThreadLibraryCalls)
 * to avoid overhead on every thread creation.
 */

#include <windows.h>
#include "hooks.h"
#include "ipc.h"
#include "dumper.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)lpvReserved;

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        dumper_init();      /* set up %TEMP%\quarry_dumps\<pid>\ before hooks fire */
        quarry_ipc_init();
        hooks_install();
        break;

    case DLL_PROCESS_DETACH:
        hooks_remove();
        quarry_ipc_teardown();
        break;
    }
    return TRUE;
}
