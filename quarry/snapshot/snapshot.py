"""
System state snapshot — captures the live state of the machine at a point in time.

Captured: running processes, loaded services, scheduled tasks, autorun entries
(registry Run keys + startup folder), and active network connections.

Requires pywin32 on Windows. Falls back to lightweight stubs on Linux (dev mode).
"""
from __future__ import annotations
import sys
import time
from typing import Any

_WINDOWS = sys.platform == "win32"
_HAS_WIN32 = False

if _WINDOWS:
    try:
        import win32process   # type: ignore[import]
        import win32service   # type: ignore[import]
        import win32api       # type: ignore[import]
        import win32con       # type: ignore[import]
        import winreg         # type: ignore[import]
        _HAS_WIN32 = True
    except ImportError:
        pass


def capture() -> dict[str, Any]:
    """Return a complete system state snapshot as a plain dict."""
    return {
        "timestamp":      time.time(),
        "processes":      _processes(),
        "services":       _services(),
        "scheduled_tasks": _scheduled_tasks(),
        "autoruns":       _autoruns(),
        "connections":    _connections(),
    }


# ------------------------------------------------------------------
# Processes
# ------------------------------------------------------------------

def _processes() -> list[dict]:
    if not _HAS_WIN32:
        return [{"pid": 4, "name": "System", "path": "", "cmdline": ""}]
    results = []
    for pid in win32process.EnumProcesses():  # type: ignore[name-defined]
        try:
            hProc = win32api.OpenProcess(  # type: ignore[name-defined]
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,  # type: ignore[name-defined]
                False, pid
            )
            mods  = win32process.EnumProcessModules(hProc)  # type: ignore[name-defined]
            path  = win32process.GetModuleFileNameEx(hProc, mods[0]) if mods else ""  # type: ignore[name-defined]
            results.append({"pid": pid, "path": path, "name": path.split("\\")[-1]})
        except Exception:
            results.append({"pid": pid, "path": "", "name": ""})
    return results


# ------------------------------------------------------------------
# Services
# ------------------------------------------------------------------

def _services() -> list[dict]:
    if not _HAS_WIN32:
        return []
    results = []
    hSCM = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)  # type: ignore[name-defined]
    try:
        svcs = win32service.EnumServicesStatusEx(hSCM)  # type: ignore[name-defined]
        for svc in svcs:
            results.append({
                "name":        svc["ServiceName"],
                "display":     svc["DisplayName"],
                "status":      svc["CurrentState"],
                "start_type":  svc.get("StartType", -1),
                "binary_path": svc.get("BinaryPathName", ""),
            })
    finally:
        win32service.CloseServiceHandle(hSCM)  # type: ignore[name-defined]
    return results


# ------------------------------------------------------------------
# Scheduled tasks
# ------------------------------------------------------------------

def _scheduled_tasks() -> list[dict]:
    if not _HAS_WIN32:
        return []
    import subprocess, json
    try:
        out = subprocess.check_output(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            timeout=10, stderr=subprocess.DEVNULL, text=True,
        )
        tasks = []
        for line in out.splitlines()[1:]:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 9:
                tasks.append({
                    "hostname": parts[0],
                    "task":     parts[1],
                    "next_run": parts[2],
                    "status":   parts[3],
                    "run_as":   parts[4] if len(parts) > 4 else "",
                    "cmd":      parts[8] if len(parts) > 8 else "",
                })
        return tasks
    except Exception:
        return []


# ------------------------------------------------------------------
# Autoruns (registry Run keys + startup folder)
# ------------------------------------------------------------------

_RUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE if _HAS_WIN32 else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER if _HAS_WIN32 else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE if _HAS_WIN32 else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]


def _autoruns() -> list[dict]:
    if not _HAS_WIN32:
        return []
    results = []
    for hive, path in _RUN_KEYS:
        try:
            key = winreg.OpenKey(hive, path)  # type: ignore[name-defined]
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)  # type: ignore[name-defined]
                    results.append({"hive": _hive_name(hive), "key": path,
                                    "name": name, "value": data})
                    i += 1
                except OSError:
                    break
        except OSError:
            continue
    return results


def _hive_name(hive) -> str:
    if not _HAS_WIN32:
        return ""
    if hive == winreg.HKEY_LOCAL_MACHINE:  # type: ignore[name-defined]
        return "HKLM"
    if hive == winreg.HKEY_CURRENT_USER:   # type: ignore[name-defined]
        return "HKCU"
    return "?"


# ------------------------------------------------------------------
# Network connections
# ------------------------------------------------------------------

def _connections() -> list[dict]:
    try:
        import subprocess
        out = subprocess.check_output(
            ["netstat", "-nao"],
            timeout=10, stderr=subprocess.DEVNULL, text=True,
        )
        conns = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] in ("TCP", "UDP"):
                conns.append({
                    "proto":  parts[0],
                    "local":  parts[1],
                    "remote": parts[2] if parts[0] == "TCP" else "",
                    "state":  parts[3] if parts[0] == "TCP" else "",
                    "pid":    int(parts[-1]) if parts[-1].isdigit() else 0,
                })
        return conns
    except Exception:
        return []
