# Quarry Source File Reference

One-line-plus description of every `.py` file under `quarry/`, grouped by package.
See [../ARCHITECTURE.md](../ARCHITECTURE.md) for how these pieces fit together.

## `quarry/`

- **`cli.py`** — Click-based CLI entry point (`quarry` command). Defines the
  `start`, `inject`, `static`, and `report` subcommands and wires them to
  `AnalysisSession`, the injector, `pe_analyzer`, and the export modules.
- **`session.py`** — `AnalysisSession`, the orchestrator that wires together
  the ETW session, per-domain collectors, hook IPC server, child injector,
  session store, snapshots, and the FastAPI/uvicorn UI, and drives the
  start → run → stop lifecycle.

## `quarry/models/`

- **`event.py`** — The unified `Event` dataclass (`event_type`, `timestamp`,
  `pid`/`ppid`, `process_name`, `data`) produced by every collector, plus the
  `EVENT_*` type constants.
- **`process_tree.py`** — In-memory `ProcessTree`/`ProcessNode` structures
  keyed by PID; supports adding/terminating processes, looking up
  children/roots, and serializing to a nested dict for the UI and reports.
- **`session_store.py`** — `SessionStore`, the central thread-safe event bus.
  Owns the SQLite schema (`events`, `processes`, `snapshots`,
  `static_analysis`), the thread-safe `post()` ingestion method, the asyncio
  drain loop that persists events and fans them out to WebSocket subscriber
  queues, and snapshot/static-analysis read/write helpers.

## `quarry/collectors/`

- **`base.py`** — `Collector` ABC defining the `start()`/`stop()`/`emit()`
  contract that every domain collector implements.
- **`etw_session.py`** — `ETWSession`, the real-time ETW session manager. On
  Windows with `pywintrace` installed it subscribes to `ETW_PROVIDERS` and
  dispatches records to registered per-provider handlers; otherwise it runs a
  synthetic mock event generator (random process create/exit) so the pipeline
  is testable off-Windows.
- **`process_collector.py`** — Maps `Microsoft-Windows-Kernel-Process` records
  (process create/exit, image load) to `Event` objects.
- **`file_collector.py`** — Maps `Microsoft-Windows-Kernel-File` records
  (create/read/write/delete/rename/close/set_info) to `Event` objects.
- **`registry_collector.py`** — Maps `Microsoft-Windows-Kernel-Registry`
  records (set/delete value, create/delete/rename/open key, query) to `Event`
  objects.
- **`network_collector.py`** — Maps `Microsoft-Windows-Kernel-Network` (TCP/UDP
  connect/send/recv) and `Microsoft-Windows-DNS-Client` (query/response)
  records to `Event` objects via separate `handle_net`/`handle_dns` methods.
- **`eventlog_collector.py`** — Subscribes to the Security/System/Application
  Windows Event Log channels via `win32evtlog.EvtSubscribe` on a background
  thread per channel and emits raw XML as `Event` objects; no-op off-Windows.
- **`powershell_collector.py`** — Maps `Microsoft-Windows-PowerShell` Event ID 4104
  (Script Block Logging) records to `Event` objects. Buffers multi-fragment script
  blocks by `ScriptBlockId` and emits once reassembled — the one stateful collector
  in this package.
- **`wmi_collector.py`** — Maps `Microsoft-Windows-WMI-Activity` records (operation
  start/failure, permanent/temporary event-subscription activity, filter-to-consumer
  binding creation) to `Event` objects. Stateless like `registry_collector.py`; prefers
  the payload's `ClientProcessId` over the generic header `ProcessId` since the header
  PID for this provider is always the `WmiPrvSE.exe` host process.

## `quarry/hooks/`

- **`ipc_server.py`** — `HookIPCServer`, the named-pipe (`\\.\pipe\quarry-hooks`)
  server that accepts connections from the injected hook DLL, parses the
  32-byte binary header + payload protocol, and posts hook calls as `Event`
  objects (including SHA-256 hashing of `MEM_DUMP` payload files). Also
  defines the `HookId` enum shared conceptually with `ipc.h`.
- **`injector.py`** — DLL injection via `OpenProcess` → `VirtualAllocEx` →
  `WriteProcessMemory` → `CreateRemoteThread(LoadLibraryW)`, plus `select_dll()`
  to pick the x86/x64 hook DLL based on the target process's WOW64 status.
  Windows-only; raises `InjectionError` elsewhere.
- **`child_injector.py`** — `ChildInjector`, which subscribes to the live
  session event stream, watches for process-create events whose parent PID is
  in a transitively-growing tracked set, and schedules DLL injection into new
  children after a 400ms loader-settle delay.

### `quarry/hooks/hook_dll/` (C, not Python)

Native x86/x64 inline-trampoline hook DLL source (`dllmain.c`, `hooks.c`,
`hooks.h`, `ipc.c`, `ipc.h`, `dumper.c`, `dumper.h`) built via `CMakeLists.txt`.
Out of scope for this file — see ARCHITECTURE.md.

## `quarry/snapshot/`

- **`snapshot.py`** — `capture()` takes a point-in-time system state dict:
  running processes, services, scheduled tasks (`schtasks /query`), autorun
  registry entries (Run/RunOnce for HKLM/HKCU), and active connections
  (`netstat -nao`). Falls back to minimal stubs without `pywin32`.
- **`diff.py`** — `diff_snapshots()` compares two snapshot dicts, keying each
  category (processes by PID, services by name, scheduled tasks by task name,
  autoruns by hive+key+name, connections by proto+local+remote) to produce
  `added`/`removed`/`changed` lists per category.

## `quarry/analysis/`

- **`correlator.py`** — `correlate()` groups events by PID within a sliding
  time window (default 2s), splitting into a new `Correlation` group after a
  gap, and tags each group (`process+file`, `process+registry`,
  `file+network`, `injection-pattern`, `crypto-activity`) based on the event
  types/hook names it contains.
- **`ioc_extractor.py`** — `extract()` does a single pass over events to
  collect an `IOCs` dataclass: non-private/loopback IP addresses, domains
  (from DNS events and a regex sweep of all string field values), noteworthy
  file paths (filtering System32/SysWOW64/WinSxS noise), persistence-relevant
  registry keys (Run, RunOnce, Winlogon, Services, AppInit_DLLs), and
  on-demand SHA-256 file hashes.
- **`yara_scanner.py`** — `YaraScanner` is an event-driven live component (not
  a post-hoc pure function like the other two) — it subscribes to
  `SessionStore` and reacts to `EVENT_FILE` writes (debounced per-path, 500ms
  quiet window, cancel-and-replace on new writes to the same path) and
  `EVENT_HOOK` `MEM_DUMP` events (scanned immediately). Compiles rules once at
  `run()` start via `yara.compile()`, from a single file or a directory of
  `*.yar`/`*.yara` files (namespaced by filename stem). Emits `EVENT_YARA`
  events only when `rules.match()` finds at least one match; skips silently on
  missing files, oversized files (>100MB), and `yara.Error`.

## `quarry/static/`

- **`pe_analyzer.py`** — `analyze()` runs static PE analysis on a binary via
  `pefile`: header fields, per-section entropy, import table with a
  suspicious-API allowlist, exports, overlay detection, ASCII/UTF-16 string
  extraction, known-packer section-name matching, structural anomaly
  detection (bad timestamps, missing imports, entry point in last section,
  W+X sections), and a weighted 0–100 risk score with human-readable
  indicators. Always returns a plain dict, degrading gracefully on parse
  errors or a missing `pefile` dependency.

## `quarry/export/`

- **`json_export.py`** — `export_session()` serializes events, the process
  tree, IOCs, optional static analysis, and the pre/post snapshot diff into a
  single JSON document.
- **`report.py`** — `generate()` renders a self-contained dark-themed HTML
  report (static analysis summary, IOC table, snapshot diff, embedded process
  tree JSON, collapsible colour-coded event timeline) from the same session
  data; also exposes `_static_section()`/`_esc()`, reused by `cli.py`'s
  `quarry static --format html`.

## `quarry/ui/`

- **`server.py`** — FastAPI app (`quarry.ui.server.app`) serving the workbench:
  `GET /` (index page), REST endpoints (`/api/status`, `/api/events`,
  `/api/tree`, `/api/iocs`, `/api/static`, `/api/diff`), session control
  (`POST /api/session/stop`, `POST /api/session/track/{pid}`), and the
  `/ws/events` WebSocket that replays the last 200 buffered events then
  streams live ones with a 1-second keepalive ping. `configure()` injects the
  live `SessionStore`/`AnalysisSession` before uvicorn starts.

  (`templates/index.html`, `static/app.js`, `static/style.css` under this
  directory are the frontend — not Python, out of scope here.)
