"""Collector: Microsoft-Windows-PowerShell (Event ID 4104 — Script Block Logging)

Unlike every other collector in this package, this one is stateful: large or
obfuscated script blocks are split by the ETW provider into multiple events
sharing a ScriptBlockId, so fragments must be buffered and reassembled before
a single Event can be emitted. See ARCHITECTURE.md for the rationale.
"""
from __future__ import annotations
from typing import Callable

from quarry.collectors.base import Collector
from quarry.models.event import Event, EVENT_POWERSHELL

PROVIDER = "Microsoft-Windows-PowerShell"

_EID_SCRIPT_BLOCK = 4104

_MAX_TRACKED_BLOCKS  = 256       # cap on concurrently-tracked incomplete ScriptBlockIds
_MAX_SCRIPT_TEXT_LEN = 200_000   # 200KB cap on the final joined script_text


class PowerShellCollector(Collector):
    PROVIDER = PROVIDER

    def __init__(self, emit: Callable[[Event], None]) -> None:
        super().__init__(emit)
        # ScriptBlockId -> {"parts": {MessageNumber: chunk}, "total": int,
        #                    "path": str, "pid": int}
        self._buffers: dict[str, dict] = {}

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False
        self._buffers.clear()

    def handle(self, record: dict) -> None:
        if record.get("EventId", 0) != _EID_SCRIPT_BLOCK:
            return

        block_id = record.get("ScriptBlockId", "")
        if not block_id:
            return

        entry = self._buffers.get(block_id)
        if entry is None:
            if len(self._buffers) >= _MAX_TRACKED_BLOCKS:
                del self._buffers[next(iter(self._buffers))]  # evict oldest
            entry = {
                "parts": {},
                "total": record.get("MessageTotal", 1),
                "path":  record.get("Path", "") or "",
                "pid":   record.get("ProcessId", 0),
            }
            self._buffers[block_id] = entry

        entry["parts"][record.get("MessageNumber", 1)] = record.get("ScriptBlockText", "") or ""

        if len(entry["parts"]) < entry["total"]:
            return  # still incomplete

        del self._buffers[block_id]
        script_text = "".join(entry["parts"][i] for i in sorted(entry["parts"]))
        truncated = len(script_text) > _MAX_SCRIPT_TEXT_LEN

        self._emit(Event(
            event_type=EVENT_POWERSHELL,
            pid=entry["pid"],
            data={
                "script_block_id": block_id,
                "path":            entry["path"],
                "script_text":     script_text[:_MAX_SCRIPT_TEXT_LEN],
                "message_total":   entry["total"],
                "truncated":       truncated,
            },
        ))
