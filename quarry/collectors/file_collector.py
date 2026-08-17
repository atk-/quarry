"""Collector: Microsoft-Windows-Kernel-File"""
from __future__ import annotations
from typing import Callable

from quarry.collectors.base import Collector
from quarry.models.event import Event, EVENT_FILE

PROVIDER = "Microsoft-Windows-Kernel-File"

# Keyword flags (KERNEL_FILE_KEYWORD_*)
_KW_FILEIO    = 0x10
_KW_FILENAME  = 0x20

# EventIDs of interest
_EID_CREATE    = 12
_EID_READ      = 15
_EID_WRITE     = 16
_EID_DELETE    = 26
_EID_RENAME    = 10
_EID_CLOSE     = 14
_EID_SET_INFO  = 19


class FileCollector(Collector):
    PROVIDER = PROVIDER

    def __init__(self, emit: Callable[[Event], None]) -> None:
        super().__init__(emit)

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def handle(self, record: dict) -> None:
        eid  = record.get("EventId", 0)
        path = record.get("FileName", "") or record.get("OpenPath", "")
        # ProcessId comes from the ETW event header (present on every record,
        # same field used by ProcessCollector/RegistryCollector). IssuingThreadId
        # is a Kernel-File-specific payload field for the I/O-issuing thread —
        # not the same thing as the owning process, so it's kept as auxiliary
        # "tid" data rather than used for pid attribution.
        pid = record.get("ProcessId", 0)
        tid = record.get("IssuingThreadId", 0)

        op_map = {
            _EID_CREATE:   "create",
            _EID_READ:     "read",
            _EID_WRITE:    "write",
            _EID_DELETE:   "delete",
            _EID_RENAME:   "rename",
            _EID_CLOSE:    "close",
            _EID_SET_INFO: "set_info",
        }
        op = op_map.get(eid)
        if op is None:
            return

        data: dict = {"op": op, "path": path, "tid": tid}
        if op == "write":
            data["bytes"] = record.get("IoSize", 0)
        if op == "rename":
            data["new_path"] = record.get("NewFileName", "")

        self._emit(Event(
            event_type=EVENT_FILE,
            pid=pid,
            data=data,
        ))
