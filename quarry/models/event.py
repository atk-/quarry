from __future__ import annotations
import json
import time
from dataclasses import dataclass, field
from typing import Any

EVENT_PROCESS  = "process"
EVENT_FILE     = "file"
EVENT_REGISTRY = "registry"
EVENT_NETWORK  = "network"
EVENT_HOOK     = "hook"
EVENT_EVENTLOG = "eventlog"


@dataclass
class Event:
    event_type:   str
    timestamp:    float          = field(default_factory=time.time)
    pid:          int            = 0
    ppid:         int            = 0
    process_name: str            = ""
    data:         dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type":   self.event_type,
            "timestamp":    self.timestamp,
            "pid":          self.pid,
            "ppid":         self.ppid,
            "process_name": self.process_name,
            "data":         self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
