"""Collector: Microsoft-Windows-Kernel-Process"""
from __future__ import annotations
from typing import Callable

from quarry.collectors.base import Collector
from quarry.models.event import Event, EVENT_PROCESS

PROVIDER = "Microsoft-Windows-Kernel-Process"

# Event IDs for this provider
_EID_PROCESS_CREATE = 1
_EID_PROCESS_EXIT   = 2
_EID_THREAD_CREATE  = 3
_EID_THREAD_EXIT    = 4
_EID_IMAGE_LOAD     = 5


class ProcessCollector(Collector):
    PROVIDER = PROVIDER

    def __init__(self, emit: Callable[[Event], None]) -> None:
        super().__init__(emit)

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def handle(self, record: dict) -> None:
        eid = record.get("EventId", 0)
        if eid == _EID_PROCESS_CREATE:
            self._emit(Event(
                event_type=EVENT_PROCESS,
                pid=record.get("ProcessId", 0),
                ppid=record.get("ParentId", 0),
                process_name=_basename(record.get("ImageFileName", "")),
                data={
                    "sub_type":   "create",
                    "image_path": record.get("ImageFileName", ""),
                    "cmdline":    record.get("CommandLine", ""),
                },
            ))
        elif eid == _EID_PROCESS_EXIT:
            self._emit(Event(
                event_type=EVENT_PROCESS,
                pid=record.get("ProcessId", 0),
                process_name=_basename(record.get("ImageFileName", "")),
                data={
                    "sub_type":  "exit",
                    "exit_code": record.get("ExitCode", 0),
                },
            ))
        elif eid == _EID_IMAGE_LOAD:
            self._emit(Event(
                event_type=EVENT_PROCESS,
                pid=record.get("ProcessId", 0),
                data={
                    "sub_type":   "image_load",
                    "image_path": record.get("FileName", ""),
                    "image_size": record.get("ImageSize", 0),
                    "image_base": record.get("ImageBase", 0),
                },
            ))


def _basename(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1]
