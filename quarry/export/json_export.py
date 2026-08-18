from __future__ import annotations
import json
from typing import Any, TextIO

from quarry.models.event import Event
from quarry.models.process_tree import ProcessTree
from quarry.analysis.ioc_extractor import IOCs
from quarry.analysis.mitre_mapper import TechniqueMatch
from quarry.snapshot.diff import diff_snapshots


def export_session(
    events: list[Event],
    tree: ProcessTree,
    iocs: IOCs,
    pre_snapshot: dict | None,
    post_snapshot: dict | None,
    out: TextIO,
    indent: int = 2,
    static_analysis: dict | None = None,
    techniques: list[TechniqueMatch] | None = None,
) -> None:
    payload: dict[str, Any] = {
        "event_count":    len(events),
        "process_tree":   tree.to_dict(),
        "iocs":           iocs.to_dict(),
        "events":         [e.to_dict() for e in events],
    }
    if static_analysis:
        payload["static_analysis"] = static_analysis
    if techniques:
        payload["mitre_techniques"] = [t.to_dict() for t in techniques]
    if pre_snapshot and post_snapshot:
        payload["snapshot_diff"] = diff_snapshots(pre_snapshot, post_snapshot)

    json.dump(payload, out, indent=indent, default=str)
