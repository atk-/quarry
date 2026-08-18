"""
MITRE ATT&CK technique mapper — maps observed events/correlations to ATT&CK
technique IDs. Deliberately conservative: only tags techniques with a
reasonably direct, low-noise signal (e.g. the classic injection triad, a
registry write to a known persistence key, a WMI consumer binding). Does not
attempt broad/speculative inference (e.g. tagging every outbound connection
as C2 communication) — false positives in a security tool are worse than
gaps, and false positives are cheap to introduce by over-inferring from a
single weak signal.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from quarry.models.event import (
    Event, EVENT_HOOK, EVENT_REGISTRY, EVENT_WMI, EVENT_POWERSHELL, EVENT_YARA,
)
from quarry.analysis.correlator import correlate

# technique_id -> (name, tactic)
_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1055":     ("Process Injection", "Defense Evasion"),
    "T1027":     ("Obfuscated Files or Information", "Defense Evasion"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence"),
    "T1547.004": ("Boot or Logon Autostart Execution: Winlogon Helper DLL", "Persistence"),
    "T1546.003": ("Event Triggered Execution: WMI Event Subscription", "Persistence"),
    "T1546.010": ("Event Triggered Execution: AppInit DLLs", "Persistence"),
    "T1546.012": ("Event Triggered Execution: Image File Execution Options Injection", "Persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
}

# registry key substring -> technique_id (first match wins)
_REGISTRY_TECHNIQUES: list[tuple[str, str]] = [
    (r"CurrentVersion\Run", "T1547.001"),
    (r"CurrentVersion\RunOnce", "T1547.001"),
    ("Winlogon", "T1547.004"),
    ("Image File Execution Options", "T1546.012"),
    ("AppInit_DLLs", "T1546.010"),
    (r"Services\\", "T1543.003"),
]


@dataclass
class TechniqueMatch:
    technique_id: str
    name: str
    tactic: str
    evidence: list[str] = field(default_factory=list)
    pids: set[int] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name":         self.name,
            "tactic":       self.tactic,
            "evidence":     sorted(set(self.evidence)),
            "pids":         sorted(self.pids),
        }


def map_techniques(events: list[Event]) -> list[TechniqueMatch]:
    matches: dict[str, TechniqueMatch] = {}

    def _tag(technique_id: str, evidence: str, pid: int) -> None:
        if technique_id not in _TECHNIQUES:
            return
        name, tactic = _TECHNIQUES[technique_id]
        m = matches.setdefault(technique_id, TechniqueMatch(technique_id, name, tactic))
        m.evidence.append(evidence)
        if pid:
            m.pids.add(pid)

    # Pass 1: correlator-derived combo signals
    for corr in correlate(events):
        hook_names = sorted({
            e.data.get("hook", "") for e in corr.events if e.event_type == EVENT_HOOK
        })
        if "injection-pattern" in corr.tags:
            _tag("T1055", f"hook sequence {hook_names} on PID {corr.pivot_pid}", corr.pivot_pid)
        if "crypto-activity" in corr.tags:
            _tag("T1027", f"crypto API(s) {hook_names} on PID {corr.pivot_pid}", corr.pivot_pid)

    # Pass 2: direct single-event signals
    for ev in events:
        if ev.event_type == EVENT_HOOK and ev.data.get("hook") == "CREATE_SERVICE":
            _tag("T1543.003", f"CreateService call on PID {ev.pid}", ev.pid)
        elif ev.event_type == EVENT_HOOK and ev.data.get("hook") == "MEM_DUMP":
            _tag("T1055", f"RW→RX memory dump on PID {ev.pid}", ev.pid)
        elif ev.event_type == EVENT_REGISTRY and ev.data.get("op") == "set_value":
            key = ev.data.get("key", "")
            for substr, tid in _REGISTRY_TECHNIQUES:
                if substr in key:
                    _tag(tid, f"registry write to {key}", ev.pid)
                    break
        elif ev.event_type == EVENT_WMI and ev.data.get("op") == "consumer_binding":
            _tag("T1546.003", f"WMI consumer binding: {ev.data.get('operation', '')}", ev.pid)
        elif ev.event_type == EVENT_POWERSHELL:
            _tag("T1059.001", f"PowerShell script block executed (PID {ev.pid})", ev.pid)
        elif ev.event_type == EVENT_YARA:
            for m in ev.data.get("matches", []):
                meta = m.get("meta", {}) or {}
                tid = meta.get("mitre_technique") or meta.get("attack_technique") or meta.get("technique_id")
                if tid:
                    _tag(tid, f"YARA rule '{m.get('rule', '')}' tagged {tid}", ev.pid)

    return sorted(matches.values(), key=lambda m: m.technique_id)
