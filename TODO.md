# Quarry — Feature TODO

Items are grouped by category and ordered roughly by impact on daily analysis work.
Checked items are implemented.

---

## Known Issues / Bugs

- [ ] **Several subscribed ETW providers have no collector wired up** — `ETW_PROVIDERS` in
  `quarry/collectors/etw_session.py` includes `Microsoft-Windows-DotNETRuntime`,
  `Microsoft-Windows-TaskScheduler`, and `Microsoft-Antimalware-Engine`, but
  `AnalysisSession.__init__()` (`quarry/session.py`) only calls `register_router()` for the
  process/file/registry/network/DNS/PowerShell/WMI-Activity providers. Events from the
  remaining three reach `ETWSession._dispatch()` and are silently dropped since no handler
  is registered.
  (`Microsoft-Windows-PowerShell` is now handled by `PowerShellCollector`;
  `Microsoft-Windows-WMI-Activity` is now handled by `WMIActivityCollector`.)

---

## Data Collection

- [x] **Auto-injection into child processes** — Watch for process-create ETW events whose
  parent PID is in the tracked set; inject the hook DLL automatically and extend tracking
  to the new child (transitively). Without this, most malware families that spawn shells
  or drop a second-stage binary are only partially visible.

- [x] **RW→RX memory region dumping** — In the `VirtualProtect` hook, detect when a
  region transitions from writable to executable and write its contents to disk. Covers the
  overwhelming majority of in-memory packers/unpackers. The dump path is sent back via IPC
  and appears as a `MEM_DUMP` hook event in the timeline.

- [ ] **Callstack capture in hook events** — Call `RtlCaptureStackBackTrace` at hook time
  and resolve frame addresses to module+offset strings. Separates noisy legitimate
  `VirtualAlloc` calls (runtime heap, JIT) from calls originating from unresolved or
  anonymous RWX regions, which are almost always malicious.

- [ ] **Anti-analysis / evasion API coverage** — Hook and flag calls to:
  `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`
  (ProcessDebugPort / ProcessDebugFlags), timing checks (`GetTickCount` / `QueryPerformanceCounter`
  delta patterns), CPUID-based VM detection, and registry/WMI queries for VMware/VirtualBox
  artifacts. Detecting these tells you the sample is aware of analysis even when it appears
  idle.

- [x] **Script engine deep parsing — PowerShell** — `PowerShellCollector`
  (`quarry/collectors/powershell_collector.py`) parses `Microsoft-Windows-PowerShell` Event
  ID 4104 (Script Block Logging), reassembling multi-fragment script blocks by
  `ScriptBlockId` and emitting the deobfuscated script text as an `EVENT_POWERSHELL` event.

- [ ] **Script engine deep parsing — VBScript/JScript** — `Microsoft-Windows-Script-Interface`
  covers VBScript/JScript and needs a dedicated collector handler, following the
  `PowerShellCollector` pattern.

- [ ] **Network payload capture (PCAP)** — ETW gives connection metadata and byte counts
  but not content. Integrate Npcap to write a PCAP file alongside the session DB. Correlate
  with network ETW events by timestamp and port so each capture frame can be attributed to
  a PID.

---

## Analysis & Detection

- [x] **YARA integration** — Load a user-supplied ruleset at session start. Scan:
  (1) any file the target writes to disk, (2) memory dump files produced by the RW→RX hook.
  Surface YARA matches as first-class events in the timeline with the matching rule name and
  tags.

- [ ] **Behavioral signature rules** — A declarative rule format (similar in spirit to Sigma)
  that fires against the event stream. Example: "process spawns child AND child writes to
  `CurrentVersion\Run` AND child makes outbound connection" → tag `dropper-persistence`.
  The correlator's current time-window grouping is a foundation but it is not queryable.

- [x] **Static pre-execution analysis** — Before launching a sample: parse its PE headers
  (machine type, subsystem, compile timestamp), extract the import table, compute section
  entropy (high entropy → likely packed), run strings extraction. Present alongside the
  runtime timeline so dynamic behavior can be read against static expectations.

---

## Reporting & Export

- [ ] **MITRE ATT&CK technique tagging** — Map observed behaviors to ATT&CK technique IDs
  (e.g. `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` → T1055 Process
  Injection). Include technique IDs in the HTML report and JSON export.

- [ ] **Threat intel enrichment** — For each extracted IOC (IP, domain, file hash), offer
  an optional VirusTotal API lookup and annotate results in the report: family classification,
  detection ratio, first/last seen.

---

## Ghidra Integration & LLM-Assisted Reverse Engineering

The goal is a Ghidra MCP server that exposes Ghidra's analysis engine as a set of
structured tools consumable by any LLM service provider (Claude, GPT-4o, etc.) and
queryable from within Quarry. The analyst should be able to ask natural-language questions
about the sample — "what does the function at the entry point do?", "find all functions
that touch the registry", "rename this function based on what it does" — and get answers
grounded in Ghidra's decompiler output rather than just strings and imports.

- [ ] **Ghidra headless project management** — Quarry opens or creates a Ghidra project for
  the current session's sample automatically, runs auto-analysis headlessly
  (`analyzeHeadless`), and keeps the project path in the session DB so subsequent
  queries land in the same already-analysed project. First analysis of a binary is the
  slow step (~30–120 s for a typical PE); results are cached in the project file so
  follow-up queries are instant.

  Design notes:
  - Requires `GHIDRA_HOME` env var or a configurable path in Quarry settings
  - Project directory: `<session_db_dir>/ghidra_projects/<sha256>/`
  - Auto-analysis script passed via `-postScript` flag to `analyzeHeadless`
  - Check for existing project before re-running analysis (idempotent)

- [ ] **Ghidra MCP server (`quarry/ghidra/mcp_server.py`)** — A local MCP server that
  bridges Ghidra's Python scripting layer to the MCP tool protocol. Runs as a sidecar
  process alongside the Quarry web server. The LLM connects to it as an MCP client and
  calls tools by name.

  Planned tool surface (MCP tool names and rough signatures):

  | Tool | Arguments | Returns |
  |---|---|---|
  | `decompile_function` | `address: int \| name: str` | decompiled C pseudocode |
  | `list_functions` | `filter?: str` | list of `{name, address, size}` |
  | `get_xrefs_to` | `address: int` | list of caller addresses + context |
  | `get_xrefs_from` | `address: int` | list of callee addresses |
  | `get_strings` | `min_len?: int` | list of `{address, value, encoding}` |
  | `get_imports` | — | list of `{dll, name, address, thunk_address}` |
  | `get_exports` | — | list of `{name, address, ordinal}` |
  | `rename_function` | `address: int, new_name: str` | confirmation |
  | `add_comment` | `address: int, comment: str, type?: EOL\|PLATE\|PRE` | confirmation |
  | `search_mnemonics` | `pattern: str` | list of matching instruction addresses |
  | `get_call_graph` | `root: int, depth?: int` | tree of call relationships |
  | `get_data_type` | `address: int` | inferred struct / type info |

  Design notes:
  - Communication between MCP server and Ghidra: Ghidra Bridge
    (`ghidra-bridge`, a Java↔Python RPC bridge), or a persistent Ghidra script that
    exposes a local socket / named pipe; evaluate which is more stable
  - MCP server process is started lazily on first tool call; stops with the Quarry session
  - Write-back tools (`rename_function`, `add_comment`) require the Ghidra project to
    not be locked by the GUI; detect lock and surface a clear error

- [ ] **Quarry ↔ Ghidra address linkage** — Hook events and memory dumps already carry
  virtual addresses (e.g. `VirtualProtect` on `0x1A3C0000`). Resolve these against
  Ghidra's module map so that a `MEM_DUMP` event in the timeline can show a "Open in
  Ghidra" button that calls `decompile_function` at that address and renders the
  pseudocode inline in the Quarry UI.

  Design notes:
  - Module base addresses come from `image_load` ETW events (EID 5 in the process
    collector); store them in the session DB alongside events
  - Address resolution: `rva = event_address - module_base`, then look up in Ghidra's
    function table by RVA
  - UI: right-click on any hook event → "Decompile" → pseudocode panel slides in

- [ ] **LLM analysis panel in the UI** — A chat-style panel in the Quarry workbench where
  the analyst can type free-form questions. The panel sends the question to a configured
  LLM provider (Claude API, OpenAI, local Ollama) with the MCP server attached as a
  tool source. The LLM autonomously calls `decompile_function`, `get_xrefs_to`, etc.
  and streams its reasoning back into the panel.

  Design notes:
  - Provider config in a `quarry.toml` or env vars (`QUARRY_LLM_PROVIDER`, `QUARRY_LLM_API_KEY`)
  - System prompt includes session context: sample path, SHA-256, static analysis
    summary, risk score, current suspicious imports — so the LLM starts with full
    triage context rather than a blank slate
  - Conversation history is persisted in the session DB (`llm_chat` table) so it
    appears in the HTML report
  - Analyst-confirmed renames / comments written back to Ghidra project via MCP tools

---

## Infrastructure

- [ ] **VM snapshot / revert controller** — A host-side `quarry-controller` module that drives
  a hypervisor (VirtualBox `VBoxManage`, VMware `vmrun`, Hyper-V PowerShell) to: revert to
  a clean snapshot, wait for the in-guest Quarry agent to come online, trigger a session,
  collect results, and repeat for a queue of samples. Tracked separately; deferred until the
  in-guest agent is stable.

---

## Known Limitations

These are constraints inherent to the current architecture (ETW + userland API hooking),
not bugs to fix or features to schedule. Worth keeping in mind when reading results or
scoping future work — some may only be addressable with a kernel driver or a fundamentally
different collection strategy.

- **Userland hooks are bypassable by direct syscalls.** The hook DLL hooks Win32-layer
  APIs (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, etc.), not the
  underlying `Nt*`/`Zw*` syscalls. Malware using direct syscall invocation (e.g.
  Hell's Gate / Halo's Gate-style evasion) or a freshly-mapped, unhooked copy of ntdll
  bypasses the hooks entirely and is invisible to that collection path.

- **ETW itself can be evaded by sufficiently privileged malware.** Patching
  `ntdll!EtwEventWrite` in-process, or disabling/tampering with providers, is a
  well-documented evasion technique. Quarry has no self-integrity checking or anti-tamper
  protection for its own collection mechanisms, and detecting such tampering is outside
  the current threat model.

- **No captured file content beyond RW→RX memory dumps.** The file collector records
  path and byte count for writes, not the written bytes. IOC hashing
  (`quarry/analysis/ioc_extractor.py`) only works if the file is still present on disk when
  extraction runs — droppers that write, execute, and delete a payload leave nothing to
  hash after the fact.

- **Network visibility is metadata-only.** ETW gives connection/DNS metadata and byte
  counts but no packet content (PCAP capture is planned — see Data Collection — but even
  once added, TLS-encrypted traffic remains opaque without a separate decryption/MITM
  strategy, which is not planned).

- **No coverage of processes running before Quarry attaches.** Injection only targets
  processes Quarry itself launches or is explicitly told to track (`quarry inject <pid>`) plus
  their descendants; pre-existing processes on the system are not retroactively hooked,
  and there's no periodic re-scan for newly-relevant processes outside the
  parent/child-tracking chain.
