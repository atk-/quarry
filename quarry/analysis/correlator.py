"""
Event correlator — links events across domains using PID and time proximity.

Returns a list of Correlation objects, each grouping events from different
collectors that likely belong to the same logical action
(e.g. a process spawning + dropping a file + writing a registry key).
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from quarry.models.event import Event


@dataclass
class Correlation:
    pivot_pid:  int
    time_start: float
    time_end:   float
    events:     list[Event] = field(default_factory=list)
    tags:       list[str]   = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pivot_pid":  self.pivot_pid,
            "time_start": self.time_start,
            "time_end":   self.time_end,
            "tags":       self.tags,
            "events":     [e.to_dict() for e in self.events],
        }


def correlate(events: list[Event], window_sec: float = 2.0) -> list[Correlation]:
    """
    Group events by PID within overlapping time windows.

    A new group is started when a gap of more than window_sec elapses between
    consecutive events for the same PID.
    """
    from itertools import groupby

    by_pid: dict[int, list[Event]] = {}
    for ev in sorted(events, key=lambda e: e.timestamp):
        by_pid.setdefault(ev.pid, []).append(ev)

    correlations: list[Correlation] = []
    for pid, pid_events in by_pid.items():
        group: list[Event] = []
        for ev in pid_events:
            if group and (ev.timestamp - group[-1].timestamp) > window_sec:
                correlations.append(_make_corr(pid, group))
                group = []
            group.append(ev)
        if group:
            correlations.append(_make_corr(pid, group))

    return sorted(correlations, key=lambda c: c.time_start)


def _make_corr(pid: int, events: list[Event]) -> Correlation:
    types = {e.event_type for e in events}
    tags: list[str] = []

    if "process" in types and "file" in types:
        tags.append("process+file")
    if "process" in types and "registry" in types:
        tags.append("process+registry")
    if "file" in types and "network" in types:
        tags.append("file+network")
    if "hook" in types:
        hook_names = {e.data.get("hook", "") for e in events if e.event_type == "hook"}
        if any("VIRTUAL" in h or "REMOTE_THREAD" in h for h in hook_names):
            tags.append("injection-pattern")
        if any("CRYPT" in h for h in hook_names):
            tags.append("crypto-activity")

    return Correlation(
        pivot_pid=pid,
        time_start=events[0].timestamp,
        time_end=events[-1].timestamp,
        events=events,
        tags=tags,
    )
