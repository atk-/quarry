"""
Named pipe server that receives hook events from injected DLLs.

Protocol (little-endian binary):
    uint32  magic      0xDAC0FFEE
    uint32  version    1
    uint64  timestamp  QPC ticks (convert via QPC frequency)
    uint32  pid
    uint32  tid
    uint32  hook_id    see HookId enum
    uint32  data_len   byte length of following payload
    uint8[] data       null-terminated strings, see per-hook layout

The server reads events on a background thread and posts them to the session
store via the thread-safe emit() callable.
"""
from __future__ import annotations
import struct
import sys
import threading
from enum import IntEnum
from typing import Callable, Optional

from quarry.models.event import Event, EVENT_HOOK

_WINDOWS   = sys.platform == "win32"
_PIPE_NAME = r"\\.\pipe\quarry-hooks"
_MAGIC     = 0xDAC0FFEE
_VERSION   = 1
# magic(4) version(4) ts(8) pid(4) tid(4) hook_id(4) data_len(4) = 32 bytes
_HDR_FMT   = "<IIQIIII"
_HDR_SIZE  = struct.calcsize(_HDR_FMT)


class HookId(IntEnum):
    VIRTUAL_ALLOC         = 1
    VIRTUAL_PROTECT       = 2
    WRITE_PROCESS_MEMORY  = 3
    CREATE_REMOTE_THREAD  = 4
    CRYPT_ENCRYPT         = 5
    CRYPT_DECRYPT         = 6
    BCRYPT_ENCRYPT        = 7
    INTERNET_CONNECT      = 8
    HTTP_SEND_REQUEST     = 9
    CREATE_SERVICE        = 10
    CHANGE_SERVICE_CONFIG = 11
    MEM_DUMP              = 12  # RW→RX region dumped; payload = file path


_HOOK_NAMES = {h.value: h.name for h in HookId}


class HookIPCServer:
    def __init__(self, emit: Callable[[Event], None]) -> None:
        self._emit = emit
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> None:
        if not _WINDOWS:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._serve, daemon=True, name="hook-ipc"
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _serve(self) -> None:
        import ctypes
        import ctypes.wintypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

        while self._running:
            pipe = kernel32.CreateNamedPipeW(
                _PIPE_NAME,
                0x00000003,   # PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED
                0x00000000,   # PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT
                255,          # nMaxInstances
                4096, 4096,   # buffer sizes
                0,            # default timeout
                None,
            )
            if pipe == ctypes.wintypes.HANDLE(-1).value:
                break

            connected = kernel32.ConnectNamedPipe(pipe, None)
            if not connected and kernel32.GetLastError() != 535:  # ERROR_PIPE_CONNECTED
                kernel32.CloseHandle(pipe)
                continue

            client_thread = threading.Thread(
                target=self._handle_client, args=(pipe,), daemon=True
            )
            client_thread.start()

    def _handle_client(self, pipe) -> None:
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]

        try:
            while self._running:
                hdr = self._read_exact(kernel32, pipe, _HDR_SIZE)
                if hdr is None:
                    break
                magic, version, ts, pid, tid, hook_id, data_len = struct.unpack(_HDR_FMT, hdr)
                if magic != _MAGIC or version != _VERSION:
                    break
                payload = self._read_exact(kernel32, pipe, data_len) or b""
                payload_str = payload.decode("utf-8", errors="replace")

                data: dict = {
                    "hook":   _HOOK_NAMES.get(hook_id, str(hook_id)),
                    "tid":    tid,
                    "ts_qpc": ts,
                }

                if hook_id == HookId.MEM_DUMP:
                    # payload is a file path; enrich with size and SHA-256
                    data["dump_path"] = payload_str
                    data.update(_hash_dump(payload_str))
                else:
                    data["payload"] = payload_str

                self._emit(Event(event_type=EVENT_HOOK, pid=pid, data=data))
        finally:
            kernel32.CloseHandle(pipe)

    @staticmethod
    def _read_exact(kernel32, pipe, n: int) -> Optional[bytes]:
        import ctypes
        buf  = ctypes.create_string_buffer(n)
        read = ctypes.wintypes.DWORD(0)
        ok   = kernel32.ReadFile(pipe, buf, n, ctypes.byref(read), None)
        if not ok or read.value != n:
            return None
        return bytes(buf)


def _hash_dump(path: str) -> dict:
    """Return size and SHA-256 for a memory dump file, non-fatally."""
    import hashlib
    try:
        data = open(path, "rb").read()
        return {
            "dump_size":   len(data),
            "dump_sha256": hashlib.sha256(data).hexdigest(),
        }
    except OSError:
        return {"dump_size": 0, "dump_sha256": ""}
