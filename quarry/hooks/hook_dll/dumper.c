/*
 * dumper.c — Write memory regions to disk for offline analysis.
 *
 * Dumps land in %TEMP%\quarry_dumps\<pid>\ and are named <addr>_<size>.bin.
 * The path is sent back to the Quarry host via IPC as a HOOK_MEM_DUMP event so
 * the host can compute a hash, run YARA, or open the file in a disassembler.
 *
 * WriteFile is used rather than fwrite to avoid CRT heap allocation inside a
 * hook detour, which risks re-entrant heap locks.
 */

#include "dumper.h"
#include <windows.h>
#include <stdio.h>

#define MAX_DUMP_BYTES (64u * 1024u * 1024u)   /* 64 MB hard cap */

static char g_dump_dir[MAX_PATH];

void dumper_init(void) {
    char tmp[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);

    /* Ensure parent directory exists first */
    char parent[MAX_PATH];
    snprintf(parent, sizeof(parent), "%squarry_dumps\\", tmp);
    CreateDirectoryA(parent, NULL);

    /* Per-process subdirectory so concurrent analyses don't collide */
    snprintf(g_dump_dir, sizeof(g_dump_dir),
             "%squarry_dumps\\%lu\\", tmp, GetCurrentProcessId());
    CreateDirectoryA(g_dump_dir, NULL);
}

char *dumper_write(LPVOID addr, SIZE_T size) {
    if (!addr || size == 0 || size > MAX_DUMP_BYTES)
        return NULL;

    char *path = (char *)LocalAlloc(LMEM_FIXED, MAX_PATH);
    if (!path) return NULL;

    /* Use pointer address as a stable, unique filename component */
    snprintf(path, MAX_PATH, "%s%p_%zu.bin", g_dump_dir, addr, size);

    HANDLE fh = CreateFileA(
        path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (fh == INVALID_HANDLE_VALUE) {
        LocalFree(path);
        return NULL;
    }

    DWORD written = 0;
    /* SEH: if the region becomes inaccessible between VirtualProtect and
     * our read (race with another thread), catch the fault and keep the
     * partial dump rather than crashing the target process. */
    __try {
        WriteFile(fh, addr, (DWORD)size, &written, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { }

    CloseHandle(fh);

    if (written == 0) {
        DeleteFileA(path);
        LocalFree(path);
        return NULL;
    }
    return path;   /* caller must LocalFree() */
}
