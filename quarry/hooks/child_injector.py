"""
ChildInjector — automatically injects the hook DLL into child processes.

Subscribes to the session store's live event stream and watches for
process-create events whose parent PID belongs to the tracked set. When one
appears the new PID is added to the tracked set (so grandchildren are caught
too) and hook DLL injection is scheduled after a short loader-settle delay.

On non-Windows the injector is a no-op; the tracking logic still runs so the
process tree is populated correctly in mock/dev mode.
"""
from __future__ import annotations
import asyncio
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from quarry.models.event import Event, EVENT_PROCESS, EVENT_HOOK

_WINDOWS = sys.platform == "win32"

_SETTLE_DELAY = 0.4   # seconds to wait after process-create before injecting;
                       # gives the Windows loader time to map ntdll / kernel32

if TYPE_CHECKING:
    from quarry.models.session_store import SessionStore


class ChildInjector:
    """
    Tracks a transitively-growing set of PIDs and injects the hook DLL into
    every process they spawn.

    Usage:
        injector = ChildInjector(root_pids={1234}, dll_dir=Path("."), store=store)
        injector.track(5678)              # register an already-hooked PID
        injector.track_and_inject(9012)   # register + hook a freshly-spawned PID
        await injector.run()              # blocks until stop() is called
    """

    def __init__(
        self,
        root_pids: set[int],
        dll_dir: Path,
        store: "SessionStore",
    ) -> None:
        self._tracked: set[int] = set(root_pids)
        self._injected: set[int] = set()
        self._dll_dir = dll_dir
        self._store = store
        self._running = False

    def track(self, pid: int) -> None:
        """Add a PID to the tracked set (e.g. after a manual quarry inject)."""
        self._tracked.add(pid)

    def track_and_inject(self, pid: int) -> None:
        """Track pid for child propagation AND schedule direct hook DLL injection into it.

        Used for processes Quarry itself launches (the --sample path), which start
        unhooked and need injection in addition to child tracking — unlike track(),
        used for externally-injected PIDs (e.g. `quarry inject`) that are already hooked.
        """
        self._tracked.add(pid)
        asyncio.create_task(self._inject_after_settle(pid), name=f"inject-{pid}")

    def stop(self) -> None:
        self._running = False

    async def run(self) -> None:
        self._running = True
        q = self._store.subscribe()
        try:
            while self._running:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue

                if (
                    event.event_type == EVENT_PROCESS
                    and event.data.get("sub_type") == "create"
                    and event.ppid in self._tracked
                    and event.pid not in self._injected
                ):
                    self._tracked.add(event.pid)
                    asyncio.create_task(
                        self._inject_after_settle(event.pid),
                        name=f"inject-{event.pid}",
                    )
        finally:
            self._store.unsubscribe(q)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _inject_after_settle(self, pid: int) -> None:
        await asyncio.sleep(_SETTLE_DELAY)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._do_inject, pid)

    def _do_inject(self, pid: int) -> None:
        if pid in self._injected:
            return
        self._injected.add(pid)

        if not _WINDOWS:
            return

        try:
            from quarry.hooks.injector import inject, select_dll, InjectionError
            dll = select_dll(self._dll_dir, pid)
            inject(pid, dll)
            self._store.post(Event(
                event_type=EVENT_HOOK,
                pid=pid,
                data={"hook": "AUTO_INJECT", "payload": f"injected {dll.name}"},
            ))
        except Exception as exc:
            self._store.post(Event(
                event_type=EVENT_HOOK,
                pid=pid,
                data={"hook": "AUTO_INJECT_FAILED", "payload": str(exc)},
            ))
