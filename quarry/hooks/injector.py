"""
DLL injector — CreateRemoteThread + LoadLibraryW.

Only functional on Windows with admin privileges. The injected DLL must match
the bitness of the target process (x64 DLL for x64 target, x86 for x86).
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes
import os
import sys
from pathlib import Path

_WINDOWS = sys.platform == "win32"

HOOK_DLL_NAME_X64 = "quarry_hooks_x64.dll"
HOOK_DLL_NAME_X86 = "quarry_hooks_x86.dll"


class InjectionError(RuntimeError):
    pass


def inject(pid: int, dll_path: Path) -> None:
    """Inject dll_path into the process identified by pid."""
    if not _WINDOWS:
        raise InjectionError("Injection only supported on Windows")
    if not dll_path.exists():
        raise InjectionError(f"Hook DLL not found: {dll_path}")

    _inject_win32(pid, str(dll_path.resolve()))


def _inject_win32(pid: int, dll_path: str) -> None:
    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT_RESERVE = 0x3000
    PAGE_READWRITE     = 0x04

    # Open target process
    hProcess = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hProcess:
        raise InjectionError(f"OpenProcess failed for PID {pid}: {_last_error()}")

    try:
        # Allocate memory for the DLL path string
        path_bytes = (dll_path + "\x00").encode("utf-16-le")
        remote_buf = k32.VirtualAllocEx(
            hProcess, None, len(path_bytes), MEM_COMMIT_RESERVE, PAGE_READWRITE
        )
        if not remote_buf:
            raise InjectionError(f"VirtualAllocEx failed: {_last_error()}")

        # Write the DLL path into target process memory
        written = ctypes.wintypes.SIZE_T(0)
        ok = k32.WriteProcessMemory(
            hProcess, remote_buf, path_bytes, len(path_bytes), ctypes.byref(written)
        )
        if not ok:
            raise InjectionError(f"WriteProcessMemory failed: {_last_error()}")

        # Get address of LoadLibraryW in kernel32 (same across processes on same OS)
        load_lib = k32.GetProcAddress(k32.GetModuleHandleW("kernel32.dll"), b"LoadLibraryW")
        if not load_lib:
            raise InjectionError("Could not resolve LoadLibraryW")

        # Spin up a remote thread executing LoadLibraryW(path)
        tid = ctypes.wintypes.DWORD(0)
        hThread = k32.CreateRemoteThread(
            hProcess, None, 0, load_lib, remote_buf, 0, ctypes.byref(tid)
        )
        if not hThread:
            raise InjectionError(f"CreateRemoteThread failed: {_last_error()}")

        # Wait for the loader to finish
        k32.WaitForSingleObject(hThread, 5000)  # 5-second timeout
        k32.CloseHandle(hThread)
    finally:
        k32.CloseHandle(hProcess)


def _last_error() -> str:
    return f"Win32 error {ctypes.windll.kernel32.GetLastError()}"  # type: ignore[attr-defined]


def select_dll(dll_dir: Path, target_pid: int) -> Path:
    """Return the correct bitness DLL for the given target process."""
    if not _WINDOWS:
        raise InjectionError("Windows only")

    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    PROCESS_QUERY_INFO = 0x0400
    hProcess = k32.OpenProcess(PROCESS_QUERY_INFO, False, target_pid)
    is_wow64 = ctypes.wintypes.BOOL(False)
    k32.IsWow64Process(hProcess, ctypes.byref(is_wow64))
    k32.CloseHandle(hProcess)

    # If the target is a 32-bit process running under WOW64, use x86 DLL
    if is_wow64.value:
        return dll_dir / HOOK_DLL_NAME_X86
    return dll_dir / HOOK_DLL_NAME_X64
