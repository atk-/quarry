# Quarry Architecture

Quarry is a Windows malware analysis workbench. It replaces the usual juggling of ProcMon, Regshot, Wireshark, and Process Hacker with a single process that owns data collection, correlation, and a live web UI — all writing to one SQLite session file.

---

## High-level data flow

```
Windows kernel / DLLs
        │
        ├─ ETW real-time session ──────► ETWSession (background thread)
        │                                     │
        │   provider dispatch                 │  register_router()
        │   ┌──────────────────────────────── │ ──────────────────────────┐
        │   │  ProcessCollector               │  FileCollector             │
        │   │  RegistryCollector              │  NetworkCollector          │
        │   │  EventLogCollector              └──────────────────────────┘
        │   └───────────────────────────────────┐
        │                                       │ emit(Event)  [thread-safe]
        └─ Hook DLL (injected) ──named pipe──► HookIPCServer
                                                │
                                                ▼
                                         SessionStore.post()
                                         [asyncio queue, thread-safe bridge]
                                                │
                              ┌─────────────────┤
                              │                 │
                       SQLite (aiosqlite)   WebSocket fan-out
                       session.db           connected browsers
```

There is one ingestion path: every event — regardless of source — becomes an `Event` dataclass and is posted to `SessionStore.post()`. That method is the only thread-safe boundary; everything downstream is asyncio.

---

## Layer-by-layer breakdown

### Models (`quarry/models/`)

**`event.py`** — The unified event type. All collectors produce `Event` instances with these fields:

| Field | Type | Notes |
|---|---|---|
| `event_type` | str | `process`, `file`, `registry`, `network`, `hook`, `eventlog` |
| `timestamp` | float | Unix timestamp (sub-millisecond) |
| `pid` / `ppid` | int | Process and parent IDs |
| `process_name` | str | Short image name, e.g. `notepad.exe` |
| `data` | dict | Type-specific payload (see each collector) |

**`process_tree.py`** — In-memory tree of `ProcessNode` objects, keyed by PID. Updated live as process-create and process-exit events arrive. Used by both the UI's tree panel and the HTML report.

**`session_store.py`** — Central event bus. Three responsibilities:
1. Accepts events from any thread via `post()` (uses `loop.call_soon_threadsafe` to enqueue into asyncio).
2. Drains the queue in `run()` (an asyncio task): writes each event to SQLite, updates the in-memory process tree, fans out to subscriber queues.
3. Manages WebSocket subscribers: `subscribe()` returns a per-connection `asyncio.Queue`; `unsubscribe()` removes it. The drain loop copies every event into all subscriber queues (dropping on overflow rather than blocking).

### Collectors (`quarry/collectors/`)

**`etw_session.py`** — Manages a single real-time ETW session covering all configured providers. On Windows with `pywintrace` installed, it calls `ETW(providers=..., event_callback=self._dispatch)` and routes each callback by `ProviderName` to the registered handler. On non-Windows (or without pywintrace) it emits a synthetic stream of process events so the full pipeline can be tested during development.

Each domain collector is a thin mapper:

| Collector | ETW Provider | What it produces |
|---|---|---|
| `ProcessCollector` | `Microsoft-Windows-Kernel-Process` | process create/exit, image load |
| `FileCollector` | `Microsoft-Windows-Kernel-File` | create, read, write, delete, rename |
| `RegistryCollector` | `Microsoft-Windows-Kernel-Registry` | set_value, create_key, delete_key, rename_key |
| `NetworkCollector` | `Microsoft-Windows-Kernel-Network` + `Microsoft-Windows-DNS-Client` | TCP/UDP connect/send/recv, DNS queries |
| `EventLogCollector` | Win32 `EvtSubscribe` | Security / System / Application channels |
| `PowerShellCollector` | `Microsoft-Windows-PowerShell` | Reassembled PowerShell Script Block Logging (EID 4104) text |
| `WMIActivityCollector` | `Microsoft-Windows-WMI-Activity` | WMI operation start/failure, permanent/temporary event-subscription activity, `__FilterToConsumerBinding` creation (persistence) |

Collectors implement the `Collector` ABC (`base.py`): `start()`, `stop()`, and a `handle(record)` method that the ETW session calls. With one deliberate exception, they are stateless — they map raw ETW record dicts to `Event` objects and emit them; no buffering or state lives inside a collector. The exception is `PowerShellCollector`: EID 4104 (Script Block Logging) splits large/obfuscated script text across multiple ETW events sharing a `ScriptBlockId`, so the collector buffers fragments per block until all arrive, then emits one reassembled `Event`. This buffer is bounded (oldest-entry eviction past a fixed count of concurrently-tracked incomplete blocks) so a script block that never completes can't grow memory without limit.

### Hook DLL (`quarry/hooks/hook_dll/`)

A native C DLL injected into the target process to catch APIs that ETW does not expose well.

**Hooking mechanism** — 12-byte inline trampoline on x64:
```
target func:
  [saved bytes replaced with] → MOV RAX, detour_addr ; JMP RAX   (12 bytes)

trampoline (allocated with VirtualAlloc RWX):
  [original 12 bytes] → MOV RAX, target+12 ; JMP RAX
```
The detour calls `quarry_ipc_send()` then tail-calls through the trampoline to preserve original semantics.

**Hooked APIs (initial set):**

| API | Hook ID | Why ETW misses it |
|---|---|---|
| `VirtualAlloc` | 1 | Shellcode staging (RWX) |
| `VirtualProtect` | 2 | RW→RX transitions |
| `WriteProcessMemory` | 3 | Classic injection step |
| `CreateRemoteThread` | 4 | Classic injection step |
| `CryptEncrypt` / `CryptDecrypt` | 5–6 | WinCrypt API, no ETW provider |
| `BCryptEncrypt` | 7 | CNG API, no ETW provider |
| `InternetConnect` / `HttpSendRequest` | 8–9 | WinInet (ETW only sees raw TCP) |
| `CreateService` / `ChangeServiceConfig` | 10–11 | Service persistence |

**IPC protocol** — The host creates `\\.\pipe\quarry-hooks` as a named pipe server before injection. The DLL connects on `DLL_PROCESS_ATTACH` and sends a fixed 32-byte header for each hooked call, followed by a variable-length UTF-8 payload:

```
offset  size  field
0       4     magic      0xDAC0FFEE
4       4     version    1
8       8     timestamp  QueryPerformanceCounter ticks
16      4     pid
20      4     tid
24      4     hook_id
28      4     data_len
32      …     payload (hook-specific key=value string)
```

`HookIPCServer` (`quarry/hooks/ipc_server.py`) accepts connections on a background thread. Each connection gets its own handler thread. Events are converted to `Event(event_type="hook", ...)` and posted to the store.

**Injection** (`quarry/hooks/injector.py`) — `CreateRemoteThread` → `LoadLibraryW`. `select_dll()` checks whether the target is a WOW64 process (32-bit on 64-bit OS) to pick the correct DLL bitness.

### Snapshot (`quarry/snapshot/`)

`snapshot.py` captures a point-in-time system state dict covering:
- Running processes (PID, path, name)
- Windows services (name, binary path, status, start type)
- Scheduled tasks (via `schtasks /query`)
- Autorun entries (registry `Run` / `RunOnce` keys for HKLM and HKCU)
- Active network connections (via `netstat -nao`)

`diff.py` compares two snapshots by keying each category on a stable identifier (PID, service name, task name, etc.) and produces `added`, `removed`, `changed` lists per category. This is the mechanism for detecting persistence installation, new services, and backdoor connections.

### Analysis (`quarry/analysis/`)

**`correlator.py`** — Groups events by PID within time windows (default: 2 seconds). A gap larger than the window starts a new `Correlation` group. Each group is tagged based on the combination of event types it contains: `process+file`, `injection-pattern` (VirtualAlloc/CreateRemoteThread hooks), `crypto-activity`, etc.

**`ioc_extractor.py`** — Single-pass scan over the event list. Extracts:
- **IPs** — from network events `dst_addr`; skips private/loopback
- **Domains** — from DNS events and regex sweep of all string values in event data
- **File paths** — from file events; filters out noisy `System32` / `SysWOW64` / `WinSxS` paths
- **Registry keys** — from registry events; keeps only persistence-adjacent keys (Run, RunOnce, Winlogon, Services, AppInit_DLLs, IFEO)
- **File hashes** — SHA-256, computed on demand if `hash_files=True` and the file is accessible

**`yara_scanner.py`** — `YaraScanner` is a live component, not a post-hoc scan: it subscribes to the store's event stream (same pattern as `ChildInjector`) and reacts to two triggers. Files the target writes to disk are scanned with a 500ms per-path debounce (write bursts collapse into one scan; not gated on a file-close event since some malware never closes handles promptly). RW→RX memory dumps (`MEM_DUMP` hook events) are scanned immediately since the dump is already closed on disk by the time the event exists. Both run `yara.Rules.match()` off the event loop via `run_in_executor`. Matches are posted back as `EVENT_YARA` events carrying the matching rule name(s), tags, and metadata; a scanner with no rules loaded (bad path, compile error, or `yara-python` missing) self-disables at startup and never subscribes.

### Export (`quarry/export/`)

**`json_export.py`** — Serialises the full session (events, process tree, IOCs, snapshot diff) to JSON.

**`report.py`** — Generates a self-contained HTML file with a dark terminal aesthetic. Sections: IOC table, snapshot diff, process tree (embedded JSON), and a collapsible event timeline with per-type colour-coded badges.

### UI (`quarry/ui/`)

FastAPI application served by uvicorn on `http://127.0.0.1:8765` (configurable). REST endpoints for querying session data; WebSocket endpoint `/ws/events` for live streaming.

On WebSocket connect, the server replays the last 200 buffered events (so the page isn't blank on a late connection), then streams new events as they arrive. Keepalive pings are sent every second while idle.

The frontend (`static/app.js`, `static/style.css`, `templates/index.html`) is vanilla JS with no build step:
- Left panel: process tree — nodes added in real time as process-create events arrive, click to filter the timeline to that PID
- Centre panel: timeline — event rows with timestamp, type badge, PID, process name, and a one-line summary; auto-scrolls when the user is at the bottom
- Right panel: detail — click any row to expand all event fields
- Filter bar: text search, event type selector, PID input; all filters apply in combination

### CLI (`quarry/cli.py`)

Three subcommands via Click:

```
quarry start  [--output session.db] [--sample binary.exe] [--port 8765] [--host 127.0.0.1]
quarry inject <pid> [--dll-dir .]
quarry report --input session.db [--format html|json] [--output report.html]
```

`quarry start` is the primary entry point: it creates an `AnalysisSession`, which orchestrates the full startup sequence and runs uvicorn + the store drain loop concurrently under asyncio.

---

## Threading model

```
Main thread (asyncio event loop)
├── store.run()          — drains event queue, writes SQLite, fans out to WS
├── uvicorn              — serves HTTP and WebSocket
└── _wait_for_stop()     — handles SIGINT/SIGTERM

Background threads (daemon)
├── ETWSession           — pywintrace ProcessTrace() loop (blocks until stopped)
├── HookIPCServer._serve — accept loop for named pipe connections
│   └── per-client thread for each injected process
└── EventLogCollector    — EvtSubscribe loop per channel (Security/System/Application)
```

The only shared state crossing the thread boundary is `SessionStore.post()`. Everything else is asyncio-only or thread-local.

---

## Session lifecycle

```
quarry start
  │
  ├─ SessionStore.open()        create / open SQLite, start asyncio loop
  ├─ snapshot.capture()         pre-snapshot → store
  ├─ ETWSession.start()         ETW session live
  ├─ HookIPCServer.start()      named pipe server listening
  ├─ EventLogCollector.start()  EVTX subscription active
  ├─ uvicorn.serve()            UI available at http://localhost:8765
  │
  │  [events flowing in, analyst working in the browser]
  │
  Ctrl+C (or POST /api/session/stop)
  │
  ├─ ETWSession.stop()          flush + close ETW session
  ├─ HookIPCServer.stop()       close pipe server
  ├─ EventLogCollector.stop()   unsubscribe
  ├─ snapshot.capture()         post-snapshot → store
  └─ SessionStore.close()       flush SQLite, close connection
```

The session DB is a complete, self-contained record. `quarry report` reads it without the rest of the system being active.

---

## SQLite schema

```sql
events      (id, timestamp, pid, ppid, process_name, event_type, data JSON)
processes   (pid PK, ppid, name, image_path, cmdline, start_time, end_time)
snapshots   (id, kind TEXT, timestamp, data JSON)
```

Indexes on `events(pid)`, `events(event_type)`, `events(timestamp)` keep the report queries fast even for large sessions.

---

## Adding a new collector

1. Create `quarry/collectors/foo_collector.py` extending `Collector` with a `handle(record: dict)` method.
2. Register its ETW provider in `ETWSession.ETW_PROVIDERS`.
3. In `session.py`, instantiate it and wire it: `self._etw.register_router(PROVIDER, col.handle)`.

No other files need to change. The new collector's events flow through `SessionStore` automatically, appear in the UI timeline, and are included in JSON/HTML exports.

## Adding a new hook

1. Add a `HOOK_FOO = N` entry to `HookId` in both `quarry/hooks/ipc_server.py` and `quarry/hooks/hook_dll/ipc.h`.
2. Write the detour function in `hooks.c` following the same pattern as the existing ones (save args → `quarry_ipc_send()` → call trampoline).
3. Add it to the `entries[]` table in `hooks_install()`.
4. Rebuild the DLL.
