"""
Compare two system snapshots and surface the delta.

Each category returns a dict with three lists:
  added   — items present in `after` but not in `before`
  removed — items present in `before` but not in `after`
  changed — items present in both but with differing fields
"""
from __future__ import annotations
from typing import Any


def diff_snapshots(before: dict, after: dict) -> dict[str, Any]:
    return {
        "processes":       _diff_by_key(before["processes"],       after["processes"],       "pid"),
        "services":        _diff_by_key(before["services"],        after["services"],        "name"),
        "scheduled_tasks": _diff_by_key(before["scheduled_tasks"], after["scheduled_tasks"], "task"),
        "autoruns":        _diff_autoruns(before["autoruns"],      after["autoruns"]),
        "connections":     _diff_connections(before["connections"], after["connections"]),
    }


# ------------------------------------------------------------------
# Generic keyed diff
# ------------------------------------------------------------------

def _diff_by_key(before: list[dict], after: list[dict], key: str) -> dict:
    b = {item[key]: item for item in before if key in item}
    a = {item[key]: item for item in after  if key in item}

    added   = [a[k] for k in a if k not in b]
    removed = [b[k] for k in b if k not in a]
    changed = [
        {"before": b[k], "after": a[k]}
        for k in a if k in b and a[k] != b[k]
    ]
    return {"added": added, "removed": removed, "changed": changed}


# ------------------------------------------------------------------
# Autorun diff (key on hive+key+name triple)
# ------------------------------------------------------------------

def _diff_autoruns(before: list[dict], after: list[dict]) -> dict:
    def _id(e: dict) -> str:
        return f"{e.get('hive')}\\{e.get('key')}\\{e.get('name')}"

    b = {_id(e): e for e in before}
    a = {_id(e): e for e in after}

    added   = [a[k] for k in a if k not in b]
    removed = [b[k] for k in b if k not in a]
    changed = [
        {"before": b[k], "after": a[k]}
        for k in a if k in b and a[k] != b[k]
    ]
    return {"added": added, "removed": removed, "changed": changed}


# ------------------------------------------------------------------
# Connection diff (key on proto+local+remote)
# ------------------------------------------------------------------

def _diff_connections(before: list[dict], after: list[dict]) -> dict:
    def _id(c: dict) -> str:
        return f"{c.get('proto')}:{c.get('local')}->{c.get('remote')}"

    b = {_id(c): c for c in before}
    a = {_id(c): c for c in after}

    return {
        "added":   [a[k] for k in a if k not in b],
        "removed": [b[k] for k in b if k not in a],
        "changed": [],
    }
