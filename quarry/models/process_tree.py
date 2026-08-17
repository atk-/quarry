from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ProcessNode:
    pid:        int
    ppid:       int
    name:       str
    image_path: str            = ""
    cmdline:    str            = ""
    start_time: float          = 0.0
    end_time:   Optional[float] = None


class ProcessTree:
    def __init__(self) -> None:
        self._nodes: dict[int, ProcessNode] = {}

    def add(self, node: ProcessNode) -> None:
        self._nodes[node.pid] = node

    def terminate(self, pid: int, end_time: float) -> None:
        if pid in self._nodes:
            self._nodes[pid].end_time = end_time

    def get(self, pid: int) -> Optional[ProcessNode]:
        return self._nodes.get(pid)

    def children_of(self, pid: int) -> list[ProcessNode]:
        return [n for n in self._nodes.values() if n.ppid == pid]

    def roots(self) -> list[ProcessNode]:
        known = set(self._nodes)
        return [n for n in self._nodes.values() if n.ppid not in known]

    def to_dict(self) -> dict[str, Any]:
        def _node(n: ProcessNode) -> dict[str, Any]:
            return {
                "pid":        n.pid,
                "ppid":       n.ppid,
                "name":       n.name,
                "image_path": n.image_path,
                "cmdline":    n.cmdline,
                "start_time": n.start_time,
                "end_time":   n.end_time,
                "children":   [_node(c) for c in self.children_of(n.pid)],
            }
        return {"roots": [_node(r) for r in self.roots()]}
