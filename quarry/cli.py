"""
Quarry command-line interface.

Commands:
  quarry start   -- begin a monitoring session (ETW + hooks + UI)
  quarry inject  -- inject hook DLL into a running process
  quarry report  -- generate an HTML or JSON report from a saved session DB
"""
from __future__ import annotations
import asyncio
import sys
from pathlib import Path


import click


CONTEXT = {"help_option_names": ["-h", "--help"]}


@click.group(context_settings=CONTEXT)
@click.version_option(package_name="quarry")
def cli() -> None:
    """Quarry — Windows malware analysis workbench."""


# ── start ────────────────────────────────────────────────────────────

@cli.command()
@click.option("--output", "-o", default="session.db",
              help="Path for the SQLite session database.")
@click.option("--sample", "-s", default=None,
              help="Binary to launch, monitor, and auto-inject children of.")
@click.option("--dll-dir", "-d", default=".", show_default=True,
              help="Directory containing quarry_hooks_x64.dll / quarry_hooks_x86.dll "
                   "used for child auto-injection.")
@click.option("--port", "-p", default=8765, show_default=True,
              help="Port for the web UI.")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address for the web UI.")
def start(output: str, sample: str | None, dll_dir: str, port: int, host: str) -> None:
    """Start a monitoring session and open the web workbench."""
    from quarry.session import AnalysisSession

    session = AnalysisSession(
        db_path=output,
        sample_path=sample,
        dll_dir=Path(dll_dir),
        host=host,
        port=port,
    )

    try:
        asyncio.run(session.run())
    except KeyboardInterrupt:
        pass


# ── inject ───────────────────────────────────────────────────────────

@cli.command()
@click.argument("pid", type=int)
@click.option("--dll-dir", "-d", default=".", show_default=True,
              help="Directory containing quarry_hooks_x64.dll / quarry_hooks_x86.dll.")
@click.option("--session-url", default="http://127.0.0.1:8765", show_default=True,
              help="URL of a running Quarry session to register this PID for child tracking.")
def inject(pid: int, dll_dir: str, session_url: str) -> None:
    """Inject the hook DLL into a running process by PID.

    If a Quarry session is running, the PID is also registered for child
    auto-injection so any processes it spawns are hooked automatically.
    """
    from quarry.hooks.injector import inject as _inject, select_dll, InjectionError

    try:
        dll = select_dll(Path(dll_dir), pid)
        click.echo(f"[Quarry] Injecting {dll.name} into PID {pid}…")
        _inject(pid, dll)
        click.echo("[Quarry] Injection successful.")
    except InjectionError as e:
        click.echo(f"[Quarry] Injection failed: {e}", err=True)
        sys.exit(1)

    # Best-effort: tell the running session to track children of this PID
    try:
        import urllib.request
        req = urllib.request.Request(
            f"{session_url.rstrip('/')}/api/session/track/{pid}",
            method="POST",
        )
        urllib.request.urlopen(req, timeout=2)
        click.echo(f"[Quarry] PID {pid} registered for child tracking.")
    except Exception:
        click.echo("[Quarry] No active session found — child tracking not enabled.")


# ── static ───────────────────────────────────────────────────────────

@cli.command("static")
@click.argument("binary", type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "-f", "fmt", default="text",
              type=click.Choice(["text", "json", "html"]), show_default=True,
              help="Output format.")
@click.option("--output", "-o", "out_path", default="-",
              help="Output file (default: stdout).")
def static_cmd(binary: str, fmt: str, out_path: str) -> None:
    """Run static PE analysis on BINARY without starting a session."""
    from quarry.static.pe_analyzer import analyze

    result = analyze(binary)

    fh = open(out_path, "w") if out_path != "-" else sys.stdout
    try:
        if fmt == "json":
            import json
            json.dump(result, fh, indent=2, default=str)
            fh.write("\n")
        elif fmt == "html":
            from quarry.export.report import _static_section, _esc
            fh.write(
                "<!DOCTYPE html><html><head><meta charset='utf-8'>"
                "<title>Quarry Static Analysis</title>"
                "<style>body{font-family:monospace;background:#111;color:#ccc;margin:2rem}"
                "h1,h2{color:#0f0}table{border-collapse:collapse;width:100%;margin-bottom:1rem}"
                "th,td{border:1px solid #333;padding:4px 8px;text-align:left}"
                "th{background:#1a1a1a;color:#0f0}details summary{cursor:pointer;color:#888}"
                "</style></head><body>"
                f"<h1>Static Analysis — {_esc(binary)}</h1>"
                + _static_section(result)
                + "</body></html>\n"
            )
        else:
            _print_static_text(result)
    finally:
        if fh is not sys.stdout:
            fh.close()


def _print_static_text(r: dict) -> None:
    score = r.get("risk_score", 0)
    score_color = ("bright_green" if score < 30 else "yellow" if score < 60
                   else "bright_red" if score >= 80 else "red")

    click.echo()
    click.echo(f"  {'File:':<20} {r.get('path', '')}")
    click.echo(f"  {'SHA-256:':<20} {r.get('sha256', '')}")
    click.echo(f"  {'MD5:':<20} {r.get('md5', '')}")
    click.echo(f"  {'Size:':<20} {r.get('file_size', 0):,} bytes")
    click.echo(f"  {'Machine:':<20} {r.get('machine', '')} / "
               f"{'64-bit' if r.get('is_64bit') else '32-bit'} "
               f"({'DLL' if r.get('is_dll') else 'EXE'})")
    click.echo(f"  {'Subsystem:':<20} {r.get('subsystem', '')}")
    click.echo(f"  {'Compile time:':<20} {r.get('compile_timestamp_str', '')}")
    click.echo(f"  {'Entry point:':<20} 0x{r.get('entry_point', 0):X}")
    click.echo(f"  {'Overall entropy:':<20} {r.get('overall_entropy', 0):.3f}")
    click.secho(f"  {'Risk score:':<20} {score}/100", fg=score_color, bold=True)
    click.echo()

    if r.get("error"):
        click.secho(f"  Warning: {r['error']}", fg="yellow")
        click.echo()

    sections = r.get("sections", [])
    if sections:
        click.secho("  Sections:", bold=True)
        click.echo(f"  {'Name':<12} {'V.Size':>8}  {'Entropy':>7}  Flags")
        click.echo(f"  {'-'*12} {'-'*8}  {'-'*7}  {'─'*20}")
        for s in sections:
            ent = s["entropy"]
            ent_color = ("bright_red" if ent > 7.5 else "red" if ent > 7.0
                         else "yellow" if ent > 5.0 else "green")
            click.echo(
                f"  {s['name']:<12} {s['virtual_size']:>8,}  ",
                nl=False,
            )
            click.secho(f"{ent:>7.3f}", fg=ent_color, nl=False)
            click.echo(f"  {s.get('characteristics', '')}")
        click.echo()

    susp = r.get("suspicious_imports", [])
    if susp:
        click.secho(f"  Suspicious imports ({len(susp)}):", fg="red", bold=True)
        for fn in susp:
            click.secho(f"    • {fn}", fg="red")
        click.echo()

    clues = r.get("packer_clues", []) + r.get("anomalies", [])
    if clues:
        click.secho("  Anomalies / packer clues:", fg="yellow", bold=True)
        for c in clues:
            click.secho(f"    ! {c}", fg="yellow")
        click.echo()

    indicators = r.get("risk_indicators", [])
    if indicators:
        click.secho("  Risk indicators:", bold=True)
        for ind in indicators:
            click.echo(f"    ⚑ {ind}")
        click.echo()


# ── report ───────────────────────────────────────────────────────────

@cli.command()
@click.option("--input", "-i", "db_path", required=True,
              help="Session database produced by `quarry start`.")
@click.option("--format", "-f", "fmt", default="html",
              type=click.Choice(["html", "json"]), show_default=True)
@click.option("--output", "-o", "out_path", default="-",
              help="Output file path (default: stdout).")
def report(db_path: str, fmt: str, out_path: str) -> None:
    """Generate an HTML or JSON report from a saved session."""
    import json
    import sqlite3

    con = sqlite3.connect(db_path)
    rows = con.execute(
        "SELECT timestamp, pid, ppid, process_name, event_type, data "
        "FROM events ORDER BY timestamp"
    ).fetchall()

    from quarry.models.event import Event
    from quarry.models.process_tree import ProcessTree, ProcessNode
    from quarry.analysis.ioc_extractor import extract

    events = [
        Event(
            event_type=r[4],
            timestamp=r[0], pid=r[1], ppid=r[2],
            process_name=r[3],
            data=json.loads(r[5]),
        )
        for r in rows
    ]

    tree = ProcessTree()
    for ev in events:
        if ev.event_type == "process" and ev.data.get("sub_type") == "create":
            tree.add(ProcessNode(
                pid=ev.pid, ppid=ev.ppid, name=ev.process_name,
                image_path=ev.data.get("image_path", ""),
                cmdline=ev.data.get("cmdline", ""),
                start_time=ev.timestamp,
            ))

    iocs = extract(events)

    pre_row  = con.execute(
        "SELECT data FROM snapshots WHERE kind='pre'  ORDER BY id DESC LIMIT 1"
    ).fetchone()
    post_row = con.execute(
        "SELECT data FROM snapshots WHERE kind='post' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    pre  = json.loads(pre_row[0])  if pre_row  else None
    post = json.loads(post_row[0]) if post_row else None

    # Load static analysis if present (table may not exist in older sessions)
    static = None
    try:
        row = con.execute(
            "SELECT data FROM static_analysis ORDER BY id DESC LIMIT 1"
        ).fetchone()
        static = json.loads(row[0]) if row else None
    except Exception:
        pass

    con.close()

    fh = open(out_path, "w") if out_path != "-" else sys.stdout
    try:
        if fmt == "json":
            from quarry.export.json_export import export_session
            export_session(events, tree, iocs, pre, post, fh, static_analysis=static)
        else:
            from quarry.export.report import generate
            generate(events, tree, iocs, pre, post, fh, static_analysis=static)
    finally:
        if fh is not sys.stdout:
            fh.close()


if __name__ == "__main__":
    cli()
