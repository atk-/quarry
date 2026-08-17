"""
Session lifecycle orchestrator.

Wires together:
  - Static PE analysis (before ETW starts, if a sample is given)
  - ETWSession (event collection)
  - Per-domain collectors (route ETW records → typed Events)
  - HookIPCServer (API hook events from injected DLL)
  - ChildInjector (auto-inject into child processes of tracked PIDs)
  - SessionStore (event bus + SQLite persistence)
  - System snapshots (pre / post)
  - FastAPI server (UI)
"""
from __future__ import annotations
import asyncio
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

import uvicorn

from quarry.collectors.etw_session        import ETWSession
from quarry.collectors.process_collector  import ProcessCollector, PROVIDER as PROC_PROVIDER
from quarry.collectors.file_collector     import FileCollector,    PROVIDER as FILE_PROVIDER
from quarry.collectors.registry_collector import RegistryCollector, PROVIDER as REG_PROVIDER
from quarry.collectors.network_collector  import NetworkCollector, PROVIDER_NET, PROVIDER_DNS
from quarry.collectors.eventlog_collector import EventLogCollector
from quarry.hooks.ipc_server      import HookIPCServer
from quarry.hooks.child_injector  import ChildInjector
from quarry.models.session_store  import SessionStore
from quarry.snapshot.snapshot     import capture
from quarry.ui import server


class AnalysisSession:
    def __init__(
        self,
        db_path: str,
        sample_path: Optional[str] = None,
        dll_dir: Path = Path("."),
        host: str = "127.0.0.1",
        port: int = 8765,
    ) -> None:
        self.db_path     = db_path
        self.sample_path = sample_path
        self.dll_dir     = dll_dir
        self.host        = host
        self.port        = port

        self._store      = SessionStore(db_path)
        self._etw        = ETWSession(emit=self._store.post)
        self._hook_ipc   = HookIPCServer(emit=self._store.post)
        self._child_injector = ChildInjector(
            root_pids=set(), dll_dir=dll_dir, store=self._store,
        )

        self._proc_col = ProcessCollector(emit=self._store.post)
        self._file_col = FileCollector(emit=self._store.post)
        self._reg_col  = RegistryCollector(emit=self._store.post)
        self._net_col  = NetworkCollector(emit=self._store.post)
        self._evtlog   = EventLogCollector(emit=self._store.post)

        self._etw.register_router(PROC_PROVIDER, self._proc_col.handle)
        self._etw.register_router(FILE_PROVIDER, self._file_col.handle)
        self._etw.register_router(REG_PROVIDER,  self._reg_col.handle)
        self._etw.register_router(PROVIDER_NET,  self._net_col.handle_net)
        self._etw.register_router(PROVIDER_DNS,  self._net_col.handle_dns)

        self._stop_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Public API (called from CLI or REST)
    # ------------------------------------------------------------------

    def launch_and_track(self, path: str) -> int:
        """Spawn the sample, inject the hook DLL into it, and track it for child propagation."""
        print(f"[Quarry] Launching {path}")
        proc = subprocess.Popen([path])
        self._child_injector.track_and_inject(proc.pid)
        print(f"[Quarry] Sample PID {proc.pid} launched — hook injection scheduled, tracked for children.")
        return proc.pid

    def track_pid(self, pid: int) -> None:
        """Register an externally injected PID for child tracking."""
        self._child_injector.track(pid)

    def request_stop(self) -> None:
        self._stop_event.set()

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        print(f"[Quarry] Opening session db: {self.db_path}")
        await self._store.open()

        # ── Phase 1: static analysis (pre-execution, offline) ─────────
        if self.sample_path:
            await self._run_static_analysis(self.sample_path)

        # ── Phase 2: system pre-snapshot ──────────────────────────────
        print("[Quarry] Capturing pre-snapshot…")
        await self._store.store_snapshot("pre", capture())

        # ── Phase 3: configure UI ─────────────────────────────────────
        server.configure(
            store=self._store,
            session=self,
            meta={
                "running":     True,
                "db_path":     self.db_path,
                "sample_path": self.sample_path or "",
                "started_at":  time.time(),
            },
        )
        uv_config = uvicorn.Config(
            server.app, host=self.host, port=self.port, log_level="warning",
        )
        uv_server = uvicorn.Server(uv_config)

        # ── Phase 4: start collectors ──────────────────────────────────
        print("[Quarry] Starting ETW session…")
        self._etw.start()
        self._hook_ipc.start()
        self._evtlog.start()

        print(f"[Quarry] Workbench at http://{self.host}:{self.port}")
        print("[Quarry] Press Ctrl+C to stop and capture post-snapshot.")

        store_task    = asyncio.create_task(self._store.run(),          name="store-drain")
        injector_task = asyncio.create_task(self._child_injector.run(), name="child-injector")

        # ── Phase 5: launch sample after ETW settles (1.5 s) ──────────
        if self.sample_path:
            asyncio.create_task(
                self._deferred_launch(self.sample_path), name="sample-launch"
            )

        # ── Phase 6: run until stopped ────────────────────────────────
        try:
            await asyncio.gather(
                uv_server.serve(),
                self._wait_for_stop(uv_server),
            )
        finally:
            store_task.cancel()
            injector_task.cancel()
            await self._shutdown()

    async def _run_static_analysis(self, path: str) -> None:
        print(f"[Quarry] Running static analysis on {path}…")
        loop = asyncio.get_running_loop()
        from quarry.static.pe_analyzer import analyze
        result = await loop.run_in_executor(None, analyze, path)
        await self._store.store_static(result)
        score = result.get("risk_score", 0)
        err   = result.get("error")
        if err:
            print(f"[Quarry] Static analysis warning: {err}")
        else:
            print(f"[Quarry] Static analysis complete — risk score: {score}/100")
            if result.get("packer_clues"):
                print(f"[Quarry]   Packer clues: {'; '.join(result['packer_clues'])}")
            if result.get("suspicious_imports"):
                print(f"[Quarry]   Suspicious imports ({len(result['suspicious_imports'])}): "
                      f"{', '.join(result['suspicious_imports'][:5])}"
                      + (" …" if len(result["suspicious_imports"]) > 5 else ""))

    async def _deferred_launch(self, path: str) -> None:
        await asyncio.sleep(1.5)
        self.launch_and_track(path)

    async def _wait_for_stop(self, uv_server: uvicorn.Server) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._stop_event.set)
        while not self._stop_event.is_set():
            await asyncio.sleep(0.2)
        uv_server.should_exit = True

    async def _shutdown(self) -> None:
        print("\n[Quarry] Stopping collectors…")
        self._etw.stop()
        self._hook_ipc.stop()
        self._evtlog.stop()
        self._child_injector.stop()

        print("[Quarry] Capturing post-snapshot…")
        await self._store.store_snapshot("post", capture())
        await self._store.close()
        print(f"[Quarry] Session saved to {self.db_path}")
