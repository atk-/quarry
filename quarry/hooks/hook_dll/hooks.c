/*
 * hooks.c — Inline trampoline hooks for key Windows APIs.
 *
 * Hooking strategy (x64):
 *   1. Save the first 12 bytes of the target function.
 *   2. Write a 12-byte absolute jump to our detour at the function entry.
 *   3. Allocate a trampoline: original 12 bytes + jump back to byte 12 of target.
 *   4. In the detour: do our work, then call the trampoline to preserve semantics.
 *
 * Caveat: 12 bytes is enough for Windows API stubs (which start with
 * "MOV R10,RCX / MOV EAX,n / SYSCALL" = exactly 12 bytes for system calls, or
 * a short prologue for user-mode wrappers). A production hook manager would
 * use a disassembler to copy whole instructions.
 *
 * All hooks are installed after IPC init in DllMain, removed on detach.
 */

#include "hooks.h"
#include "ipc.h"
#include "dumper.h"
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Memory protection helpers                                           */
/* ------------------------------------------------------------------ */

/* Strip PAGE_GUARD / PAGE_NOCACHE / PAGE_WRITECOMBINE modifier bits. */
#define PROT(p) ((p) & 0xFFu)

#define HAS_WRITE(p) (  PROT(p) == PAGE_READWRITE         || \
                         PROT(p) == PAGE_WRITECOPY         || \
                         PROT(p) == PAGE_EXECUTE_READWRITE || \
                         PROT(p) == PAGE_EXECUTE_WRITECOPY )

#define HAS_EXEC(p)  (  PROT(p) == PAGE_EXECUTE           || \
                         PROT(p) == PAGE_EXECUTE_READ       || \
                         PROT(p) == PAGE_EXECUTE_READWRITE || \
                         PROT(p) == PAGE_EXECUTE_WRITECOPY )

/* Dump when the old protection was writable and the new protection is
 * executable. Catches: RW→RX (classic unpack), RW→RWX (staged shellcode),
 * and RWX→RX (shellcode finishing its write phase). */
static BOOL should_dump(DWORD old_prot, DWORD new_prot) {
    return HAS_WRITE(old_prot) && HAS_EXEC(new_prot);
}

/* ------------------------------------------------------------------ */
/* Trampoline infrastructure                                           */
/* ------------------------------------------------------------------ */

#define HOOK_BYTES 12

typedef struct {
    LPVOID  target;
    BYTE    saved[HOOK_BYTES];
    LPVOID  trampoline;   /* executable stub: saved_bytes + jmp back */
    BOOL    active;
} Hook;

static void hook_install(Hook *h, LPVOID target, LPVOID detour) {
    h->target = target;
    h->active = FALSE;

    /* Build 12-byte absolute JMP: MOV RAX, addr; JMP RAX */
    BYTE patch[HOOK_BYTES] = {
        0x48, 0xB8,                             /* MOV RAX, imm64 */
        0,0,0,0, 0,0,0,0,                       /* 8-byte address  */
        0xFF, 0xE0,                             /* JMP RAX         */
    };
    *(LPVOID *)(patch + 2) = detour;

    /* Allocate executable trampoline */
    h->trampoline = VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
    if (!h->trampoline) return;

    /* Save original bytes and copy to trampoline */
    DWORD old;
    VirtualProtect(target, HOOK_BYTES, PAGE_EXECUTE_READWRITE, &old);
    memcpy(h->saved, target, HOOK_BYTES);
    memcpy(h->trampoline, h->saved, HOOK_BYTES);

    /* Append jump-back at trampoline+12 */
    BYTE jmp_back[HOOK_BYTES] = {
        0x48, 0xB8,
        0,0,0,0, 0,0,0,0,
        0xFF, 0xE0,
    };
    *(LPVOID *)(jmp_back + 2) = (BYTE *)target + HOOK_BYTES;
    memcpy((BYTE *)h->trampoline + HOOK_BYTES, jmp_back, HOOK_BYTES);

    /* Write patch into target */
    memcpy(target, patch, HOOK_BYTES);
    VirtualProtect(target, HOOK_BYTES, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, HOOK_BYTES);

    h->active = TRUE;
}

static void hook_remove(Hook *h) {
    if (!h->active) return;
    DWORD old;
    VirtualProtect(h->target, HOOK_BYTES, PAGE_EXECUTE_READWRITE, &old);
    memcpy(h->target, h->saved, HOOK_BYTES);
    VirtualProtect(h->target, HOOK_BYTES, old, &old);
    FlushInstructionCache(GetCurrentProcess(), h->target, HOOK_BYTES);
    if (h->trampoline) VirtualFree(h->trampoline, 0, MEM_RELEASE);
    h->active = FALSE;
}

/* ------------------------------------------------------------------ */
/* Hook table                                                          */
/* ------------------------------------------------------------------ */

static Hook g_hooks[11];
static int  g_nhooks = 0;

static LPVOID resolve(const char *module, const char *fn) {
    HMODULE mod = GetModuleHandleA(module);
    if (!mod) mod = LoadLibraryA(module);
    return mod ? GetProcAddress(mod, fn) : NULL;
}

/* ------------------------------------------------------------------ */
/* Detour functions                                                    */
/* ------------------------------------------------------------------ */

/* Typedefs for original function signatures */
typedef LPVOID (WINAPI *FnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL   (WINAPI *FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL   (WINAPI *FnWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE (WINAPI *FnCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                               LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);

static Hook *g_va  = NULL;
static Hook *g_vp  = NULL;
static Hook *g_wpm = NULL;
static Hook *g_crt = NULL;

static LPVOID WINAPI detour_VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize,
                                          DWORD flAllocationType, DWORD flProtect) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "size=%zu protect=0x%lX", dwSize, flProtect);
    quarry_ipc_send(HOOK_VIRTUAL_ALLOC, buf, (uint32_t)n);
    return ((FnVirtualAlloc)g_va->trampoline)(lpAddress, dwSize, flAllocationType, flProtect);
}

static BOOL WINAPI detour_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize,
                                          DWORD flNewProtect, PDWORD lpflOldProtect) {
    /* Call through first: lpflOldProtect is an OUT parameter that VirtualProtect
     * fills with the previous protection. We need that value to decide whether
     * to dump, so we must let the real call happen before inspecting it. */
    DWORD scratch = 0;
    PDWORD out_prot = lpflOldProtect ? lpflOldProtect : &scratch;
    BOOL result = ((FnVirtualProtect)g_vp->trampoline)(
        lpAddress, dwSize, flNewProtect, out_prot);

    if (result) {
        DWORD old_prot = *out_prot;

        char buf[128];
        int n = snprintf(buf, sizeof(buf),
                         "addr=%p size=%zu old=0x%lX new=0x%lX",
                         lpAddress, dwSize, old_prot, flNewProtect);
        quarry_ipc_send(HOOK_VIRTUAL_PROTECT, buf, (uint32_t)n);

        if (should_dump(old_prot, flNewProtect)) {
            char *path = dumper_write(lpAddress, dwSize);
            if (path) {
                quarry_ipc_send(HOOK_MEM_DUMP, path, (uint32_t)strlen(path));
                LocalFree(path);
            }
        }
    }
    return result;
}

static BOOL WINAPI detour_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress,
                                              LPCVOID lpBuffer, SIZE_T nSize,
                                              SIZE_T *lpNumberOfBytesWritten) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "target_pid=%lu addr=%p size=%zu",
                     GetProcessId(hProcess), lpBaseAddress, nSize);
    quarry_ipc_send(HOOK_WRITE_PROCESS_MEMORY, buf, (uint32_t)n);
    return ((FnWriteProcessMemory)g_wpm->trampoline)(
        hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

static HANDLE WINAPI detour_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpSA,
                                                SIZE_T dwStack, LPTHREAD_START_ROUTINE fn,
                                                LPVOID lpParam, DWORD dwCreation, LPDWORD lpTid) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "target_pid=%lu start_addr=%p",
                     GetProcessId(hProcess), (void *)fn);
    quarry_ipc_send(HOOK_CREATE_REMOTE_THREAD, buf, (uint32_t)n);
    return ((FnCreateRemoteThread)g_crt->trampoline)(
        hProcess, lpSA, dwStack, fn, lpParam, dwCreation, lpTid);
}

/* ------------------------------------------------------------------ */
/* Public interface                                                    */
/* ------------------------------------------------------------------ */

void hooks_install(void) {
    struct { const char *mod; const char *fn; LPVOID detour; Hook **slot; } entries[] = {
        { "kernelbase.dll", "VirtualAlloc",         detour_VirtualAlloc,         &g_va  },
        { "kernelbase.dll", "VirtualProtect",        detour_VirtualProtect,       &g_vp  },
        { "kernelbase.dll", "WriteProcessMemory",    detour_WriteProcessMemory,   &g_wpm },
        { "kernelbase.dll", "CreateRemoteThread",    detour_CreateRemoteThread,   &g_crt },
    };

    for (int i = 0; i < (int)(sizeof(entries)/sizeof(entries[0])); i++) {
        LPVOID target = resolve(entries[i].mod, entries[i].fn);
        if (!target) continue;
        Hook *h = &g_hooks[g_nhooks++];
        *entries[i].slot = h;
        hook_install(h, target, entries[i].detour);
    }
}

void hooks_remove(void) {
    for (int i = 0; i < g_nhooks; i++) {
        hook_remove(&g_hooks[i]);
    }
    g_nhooks = 0;
}
