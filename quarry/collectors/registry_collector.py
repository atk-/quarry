"""Collector: Microsoft-Windows-Kernel-Registry"""
from __future__ import annotations
from typing import Callable

from quarry.collectors.base import Collector
from quarry.models.event import Event, EVENT_REGISTRY

PROVIDER = "Microsoft-Windows-Kernel-Registry"

_EID_SET_VALUE    = 5
_EID_DELETE_VALUE = 6
_EID_CREATE_KEY   = 1
_EID_DELETE_KEY   = 3
_EID_RENAME_KEY   = 10
_EID_OPEN_KEY     = 2
_EID_QUERY_VALUE  = 7


class RegistryCollector(Collector):
    PROVIDER = PROVIDER

    def __init__(self, emit: Callable[[Event], None]) -> None:
        super().__init__(emit)

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def handle(self, record: dict) -> None:
        eid  = record.get("EventId", 0)
        key  = record.get("KeyName", "") or record.get("RelativeName", "")
        pid  = record.get("ProcessId", 0)

        op_map = {
            _EID_SET_VALUE:    "set_value",
            _EID_DELETE_VALUE: "delete_value",
            _EID_CREATE_KEY:   "create_key",
            _EID_DELETE_KEY:   "delete_key",
            _EID_RENAME_KEY:   "rename_key",
            _EID_OPEN_KEY:     "open_key",
            _EID_QUERY_VALUE:  "query_value",
        }
        op = op_map.get(eid)
        if op is None:
            return

        data: dict = {"op": op, "key": key}
        if op == "set_value":
            data["value_name"] = record.get("ValueName", "")
            data["value_type"] = record.get("Type", 0)
            data["value_data"] = record.get("DataAsHex", "")

        self._emit(Event(
            event_type=EVENT_REGISTRY,
            pid=pid,
            data=data,
        ))
