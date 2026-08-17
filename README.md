# Quarry

Quarry is a Windows malware analysis workbench. It replaces the usual juggling of
ProcMon, Regshot, Wireshark, and Process Hacker with a single process that owns
data collection, correlation, and a live web UI — all writing to one SQLite
session file.

Live monitoring runs on Windows (it uses ETW and a hook DLL injected into the
target process), but the collectors fall back to a synthetic event stream on
non-Windows systems, so the full pipeline — storage, correlation, IOC
extraction, reporting, and the web UI — can be developed and tested on
Linux/macOS as well.

For a deeper look at how the pieces fit together, see [ARCHITECTURE.md](ARCHITECTURE.md).
Planned/unimplemented features are tracked in [TODO.md](TODO.md).

## Features

- Real-time ETW collection of process, file, registry, network, and event log activity
- A custom hook DLL (x86/x64 inline trampoline hooks) catching APIs ETW misses:
  `VirtualAlloc`/`VirtualProtect`, `WriteProcessMemory`, `CreateRemoteThread`,
  crypto APIs, WinInet, service creation
- Automatic RW→RX memory region dumping (catches most in-memory unpacking)
- Automatic injection into child processes spawned by a tracked PID
- Pre/post system snapshots (processes, services, scheduled tasks, autoruns,
  network connections) with a diff to spot persistence and new connections
- Static PE analysis (imports, section entropy, packer/anomaly detection, risk score)
- Event correlation and IOC extraction (IPs, domains, file paths, registry keys, hashes)
- Live web UI (process tree, timeline, static analysis) over WebSocket
- HTML and JSON report export, usable without the rest of the system running

## Requirements

- Python >= 3.11
- Windows, for live monitoring (ETW + hook DLL injection). `quarry static` and
  `quarry report` work on any OS.
- On Windows, the `windows` extra (`pywin32`, `pywintrace`) is required for
  live ETW sessions.
- To rebuild the hook DLL: CMake and an MSVC toolchain (see
  `quarry/hooks/hook_dll/CMakeLists.txt`).

## Installation

Using [uv](https://docs.astral.sh/uv/) (recommended — this repo ships a `uv.lock`):

```bash
uv sync                    # base install
uv sync --extra windows    # + pywin32/pywintrace, on Windows
uv sync --extra dev        # + pytest, for running the test suite
```

Or with plain pip, in a virtualenv:

```bash
pip install -e .
pip install -e ".[windows]"   # on Windows, for live ETW sessions
pip install -e ".[dev]"       # for running tests
```

Either way, this installs the `quarry` CLI entry point.

## Usage

### Start a monitoring session

```bash
quarry start --sample malware.exe --output session.db
```

This creates a session store, takes a pre-execution system snapshot, starts
the ETW session and hook IPC server, launches and monitors the sample
(auto-injecting into any child processes it spawns), and serves the live web
UI at `http://127.0.0.1:8765`. Stop with Ctrl+C (or `POST /api/session/stop`);
a post-execution snapshot is taken on shutdown.

Options:

```
quarry start [--output/-o session.db] [--sample/-s binary.exe]
             [--dll-dir/-d .] [--port/-p 8765] [--host 127.0.0.1]
```

`--dll-dir` should point to the directory containing the built
`quarry_hooks_x64.dll` / `quarry_hooks_x86.dll` (used for auto-injecting children).

### Inject into an already-running process

```bash
quarry inject <pid> --dll-dir .
```

If a `quarry start` session is currently running, this also registers the PID
with it so its children are tracked automatically.

### Static analysis (no session required)

```bash
quarry static malware.exe --format text   # or json / html
```

Parses PE headers, imports/exports, section entropy, strings, and packer
heuristics, and prints a risk score — useful for triage before ever running
the sample.

### Generate a report from a saved session

```bash
quarry report --input session.db --format html --output report.html
quarry report --input session.db --format json --output report.json
```

Reads the session database independently of a live session and produces a
self-contained HTML report (process tree, IOC table, snapshot diff, event
timeline) or a JSON export.

All commands support `-h`/`--help`.

## Building the hook DLL

The hook DLL source lives in `quarry/hooks/hook_dll/` and is built with CMake on
Windows:

```powershell
cd quarry/hooks/hook_dll
cmake -B build -A x64
cmake --build build --config Release
```

Build both x86 and x64 configurations if you need to monitor 32-bit processes
on a 64-bit OS (`quarry inject` / child auto-injection pick the right one based
on the target process's bitness).

## Running tests

```bash
uv run pytest
# or: pytest
```

## Project layout

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full breakdown of `quarry/models`,
`quarry/collectors`, `quarry/hooks`, `quarry/snapshot`, `quarry/analysis`, `quarry/export`,
`quarry/ui`, and `quarry/static`.
