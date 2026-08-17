/*
 * ipc.c — Named pipe client that forwards hook events to the Quarry host process.
 *
 * The Quarry Python process creates \\.\pipe\quarry-hooks as a server.
 * This DLL connects as a client on DLL_PROCESS_ATTACH and sends
 * HookEvent structs for each intercepted API call.
 *
 * All writes are serialized through a CRITICAL_SECTION so multiple threads
 * can safely call quarry_ipc_send() concurrently.
 */

#include "ipc.h"
#include <windows.h>
#include <stdint.h>
#include <string.h>

#define PIPE_NAME    L"\\\\.\\pipe\\quarry-hooks"
#define MAGIC        0xDAC0FFEEu
#define VERSION      1u

static HANDLE          g_pipe    = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_cs;
static BOOL            g_ready   = FALSE;

/* Header: magic(4) version(4) ts(8) pid(4) tid(4) hook_id(4) data_len(4) = 32 bytes */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t timestamp;   /* QueryPerformanceCounter ticks */
    uint32_t pid;
    uint32_t tid;
    uint32_t hook_id;
    uint32_t data_len;
} HookHeader;
#pragma pack(pop)

BOOL quarry_ipc_init(void) {
    InitializeCriticalSection(&g_cs);

    g_pipe = CreateFileW(
        PIPE_NAME,
        GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        0, NULL
    );

    if (g_pipe == INVALID_HANDLE_VALUE) {
        /* Host not running or pipe not ready — non-fatal, just disable IPC */
        return FALSE;
    }

    g_ready = TRUE;
    return TRUE;
}

void quarry_ipc_teardown(void) {
    g_ready = FALSE;
    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&g_cs);
}

void quarry_ipc_send(uint32_t hook_id, const char *payload, uint32_t payload_len) {
    if (!g_ready) return;

    LARGE_INTEGER ts;
    QueryPerformanceCounter(&ts);

    HookHeader hdr = {
        .magic     = MAGIC,
        .version   = VERSION,
        .timestamp = (uint64_t)ts.QuadPart,
        .pid       = GetCurrentProcessId(),
        .tid       = GetCurrentThreadId(),
        .hook_id   = hook_id,
        .data_len  = payload_len,
    };

    EnterCriticalSection(&g_cs);
    DWORD written = 0;
    WriteFile(g_pipe, &hdr,    sizeof(hdr),  &written, NULL);
    if (payload_len > 0) {
        WriteFile(g_pipe, payload, payload_len, &written, NULL);
    }
    LeaveCriticalSection(&g_cs);
}
