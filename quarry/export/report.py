"""
HTML behavior report generator.

Produces a self-contained single-file HTML report with:
- Summary counts
- Process tree
- IOC table
- Snapshot diff table
- Full event timeline (collapsible)
"""
from __future__ import annotations
import json
import time
from typing import TextIO

from quarry.models.event import Event
from quarry.models.process_tree import ProcessTree
from quarry.analysis.ioc_extractor import IOCs
from quarry.snapshot.diff import diff_snapshots

_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Quarry Report</title>
<style>
  body{{font-family:monospace;background:#111;color:#ccc;margin:2rem}}
  h1,h2{{color:#0f0}}
  table{{border-collapse:collapse;width:100%;margin-bottom:1rem}}
  th,td{{border:1px solid #333;padding:4px 8px;text-align:left}}
  th{{background:#1a1a1a;color:#0f0}}
  .badge{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.8em}}
  .process{{background:#003300;color:#0f0}}
  .file{{background:#002244;color:#66aaff}}
  .registry{{background:#330033;color:#ff88ff}}
  .network{{background:#333300;color:#ffff00}}
  .hook{{background:#440000;color:#ff4444}}
  .eventlog{{background:#1a1a00;color:#888}}
  .yara{{background:#332200;color:#ff8800}}
  details summary{{cursor:pointer;color:#888}}
  details[open] summary{{color:#0f0}}
</style>
</head>
<body>
<h1>Dynamic Analysis Toolkit — Behavior Report</h1>
<p>Generated: {generated} &nbsp;|&nbsp; Total events: {event_count}</p>

<h2>Static Analysis</h2>
{static_section}

<h2>IOCs</h2>
{ioc_section}

<h2>Snapshot Diff</h2>
{diff_section}

<h2>Process Tree</h2>
<pre>{tree_json}</pre>

<h2>Event Timeline</h2>
<details>
<summary>Show all {event_count} events</summary>
<table>
<tr><th>Time</th><th>Type</th><th>PID</th><th>Process</th><th>Details</th></tr>
{event_rows}
</table>
</details>

</body>
</html>
"""


def generate(
    events: list[Event],
    tree: ProcessTree,
    iocs: IOCs,
    pre_snapshot: dict | None,
    post_snapshot: dict | None,
    out: TextIO,
    static_analysis: dict | None = None,
) -> None:
    diff = diff_snapshots(pre_snapshot, post_snapshot) if (pre_snapshot and post_snapshot) else {}

    out.write(_TEMPLATE.format(
        generated=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        event_count=len(events),
        static_section=_static_section(static_analysis),
        ioc_section=_ioc_table(iocs),
        diff_section=_diff_table(diff),
        tree_json=json.dumps(tree.to_dict(), indent=2),
        event_rows="\n".join(_event_row(e) for e in events),
    ))


def _static_section(s: dict | None) -> str:
    if not s:
        return "<p>No static analysis data in this session.</p>"
    if s.get("error") and not s.get("sha256"):
        return f"<p>Static analysis error: {_esc(s['error'])}</p>"

    score = s.get("risk_score", 0)
    color = "#0f0" if score < 30 else "#fc0" if score < 60 else "#f80" if score < 80 else "#f44"

    susp_imports = s.get("suspicious_imports", [])
    sections_rows = "".join(
        f"<tr><td>{_esc(sec['name'])}</td>"
        f"<td>{sec.get('virtual_size', 0):,}</td>"
        f"<td>{sec.get('raw_size', 0):,}</td>"
        f"<td>{sec.get('entropy', 0):.3f}</td>"
        f"<td>{_esc(sec.get('characteristics', ''))}</td></tr>"
        for sec in s.get("sections", [])
    )

    indicators = "".join(
        f"<li>{_esc(i)}</li>" for i in s.get("risk_indicators", [])
    )

    return f"""
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Path</td><td>{_esc(s.get('path',''))}</td></tr>
  <tr><td>SHA-256</td><td>{_esc(s.get('sha256',''))}</td></tr>
  <tr><td>MD5</td><td>{_esc(s.get('md5',''))}</td></tr>
  <tr><td>Size</td><td>{s.get('file_size',0):,} bytes</td></tr>
  <tr><td>Machine</td><td>{_esc(s.get('machine',''))}</td></tr>
  <tr><td>Subsystem</td><td>{_esc(s.get('subsystem',''))}</td></tr>
  <tr><td>Compile time</td><td>{_esc(s.get('compile_timestamp_str',''))}</td></tr>
  <tr><td>Type</td><td>{'DLL' if s.get('is_dll') else 'EXE'} / {'64-bit' if s.get('is_64bit') else '32-bit'}</td></tr>
  <tr><td>Overall entropy</td><td>{s.get('overall_entropy',0):.3f}</td></tr>
  <tr><td>Risk score</td><td><b style="color:{color}">{score}/100</b></td></tr>
</table>
{('<p>Packer / anomaly clues: ' + '; '.join(_esc(c) for c in s.get('packer_clues',[])+s.get('anomalies',[])) + '</p>') if s.get('packer_clues') or s.get('anomalies') else ''}
{f'<p>Suspicious imports: <b>{_esc(", ".join(susp_imports))}</b></p>' if susp_imports else ''}
<details><summary>Sections</summary>
<table><tr><th>Name</th><th>V.Size</th><th>Raw</th><th>Entropy</th><th>Flags</th></tr>
{sections_rows}</table></details>
<details><summary>Risk indicators</summary><ul>{indicators}</ul></details>
"""


def _ioc_table(iocs: IOCs) -> str:
    rows = []
    for ip in sorted(iocs.ip_addresses):
        rows.append(f"<tr><td>IP</td><td>{_esc(ip)}</td></tr>")
    for d in sorted(iocs.domains):
        rows.append(f"<tr><td>Domain</td><td>{_esc(d)}</td></tr>")
    for p in sorted(iocs.file_paths):
        h = iocs.file_hashes.get(p, "")
        rows.append(f"<tr><td>File</td><td>{_esc(p)}</td><td>{h}</td></tr>")
    for k in sorted(iocs.registry_keys):
        rows.append(f"<tr><td>Registry</td><td>{_esc(k)}</td></tr>")
    if not rows:
        return "<p>No IOCs extracted.</p>"
    return f"<table><tr><th>Type</th><th>Value</th><th>Hash</th></tr>{''.join(rows)}</table>"


def _diff_table(diff: dict) -> str:
    if not diff:
        return "<p>No snapshot data.</p>"
    sections = []
    for category, delta in diff.items():
        added   = delta.get("added",   [])
        removed = delta.get("removed", [])
        if not added and not removed:
            continue
        items = [f"<li>+{_esc(str(x))}</li>" for x in added] + \
                [f"<li>-{_esc(str(x))}</li>" for x in removed]
        sections.append(f"<h3>{_esc(category)}</h3><ul>{''.join(items)}</ul>")
    return "".join(sections) or "<p>No changes detected.</p>"


def _event_row(ev: Event) -> str:
    ts      = time.strftime("%H:%M:%S", time.gmtime(ev.timestamp))
    ms      = f"{ev.timestamp % 1:.3f}"[1:]
    details = "; ".join(f"{k}={v}" for k, v in ev.data.items() if k != "sub_type")
    return (
        f"<tr>"
        f"<td>{ts}{ms}</td>"
        f"<td><span class='badge {ev.event_type}'>{ev.event_type}</span></td>"
        f"<td>{ev.pid}</td>"
        f"<td>{_esc(ev.process_name)}</td>"
        f"<td>{_esc(details[:200])}</td>"
        f"</tr>"
    )


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
