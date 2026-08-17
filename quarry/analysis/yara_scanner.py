"""
YaraScanner — scans files and memory dumps against a user-supplied YARA ruleset.

Subscribes to the session store's live event stream (same pattern as
ChildInjector) and reacts to two triggers:

  - EVENT_FILE writes: debounced per path (500ms of write quiescence) before
    scanning. Not all malware closes file handles promptly (e.g. an
    appended-to log/lock file), so scanning can't depend on ever seeing a
    "close" event — the debounce collapses write bursts into one scan while
    still guaranteeing eventual scanning.
  - EVENT_HOOK MEM_DUMP events: scanned immediately, no debounce, since the
    dump file is already fully written and closed on disk by the time the
    event exists.

Matches are posted back onto the store as EVENT_YARA events. A scanner with
no rules loaded (bad path, compile error, or yara-python not installed)
self-disables at startup and never subscribes.
"""
from __future__ import annotations
import asyncio
import contextlib
import os
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from quarry.models.event import Event, EVENT_FILE, EVENT_HOOK, EVENT_YARA

_DEBOUNCE_DELAY  = 0.5                    # seconds of write quiescence before scanning
_MAX_SCAN_BYTES  = 100 * 1024 * 1024      # 100MB hard cap
_SCAN_TIMEOUT_S  = 10                     # yara.Rules.match() timeout

if TYPE_CHECKING:
    from quarry.models.session_store import SessionStore


class YaraScanner:
    def __init__(self, rules_path: Optional[str], store: "SessionStore") -> None:
        self._rules_path = rules_path
        self._store = store
        self._rules = None
        self._running = False
        self._pending: dict[str, asyncio.Task] = {}   # path -> debounce task
        self._inflight: set[asyncio.Task] = set()      # in-progress scan tasks

    async def run(self) -> None:
        self._rules = self._compile_rules()
        if self._rules is None:
            return  # self-gates: never subscribes if no rules loaded

        self._running = True
        q = self._store.subscribe()
        try:
            while self._running:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                self._handle_event(event)
        finally:
            self._store.unsubscribe(q)
            await self._shutdown_tasks()

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------
    # Event routing
    # ------------------------------------------------------------------

    def _handle_event(self, event: Event) -> None:
        if event.event_type == EVENT_FILE and event.data.get("op") == "write":
            path = event.data.get("path")
            if not path:
                return
            old = self._pending.get(path)
            if old is not None:
                old.cancel()
            task = asyncio.create_task(
                self._debounced_scan(path, event.pid, "file_write"),
                name=f"yara-debounce-{path}",
            )
            self._pending[path] = task
            self._track_inflight(task)  # tracked for its full lifetime (debounce + scan)
        elif event.event_type == EVENT_HOOK and event.data.get("hook") == "MEM_DUMP":
            dump_path = event.data.get("dump_path")
            if dump_path:
                self._track_inflight(asyncio.create_task(
                    self._scan_now(dump_path, event.pid, "mem_dump"),
                    name=f"yara-dump-{dump_path}",
                ))

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    async def _debounced_scan(self, path: str, pid: int, source: str) -> None:
        try:
            await asyncio.sleep(_DEBOUNCE_DELAY)
        finally:
            # Only pop if this task is still the one registered for path —
            # avoids clobbering a newer replacement task's slot on stale cancel.
            if self._pending.get(path) is asyncio.current_task():
                self._pending.pop(path, None)
        await self._scan_now(path, pid, source)

    async def _scan_now(self, path: str, pid: int, source: str) -> None:
        loop = asyncio.get_running_loop()
        matches = await loop.run_in_executor(None, self._do_scan, path)
        if matches:
            self._store.post(Event(
                event_type=EVENT_YARA,
                pid=pid,
                data={"path": path, "source": source, "matches": matches},
            ))

    def _do_scan(self, path: str) -> list[dict]:
        try:
            size = os.path.getsize(path)
        except OSError:
            return []  # vanished before scan — skip silently
        if size > _MAX_SCAN_BYTES:
            print(f"[Quarry] YARA: skipping oversized file ({size} bytes): {path}")
            return []

        import yara
        try:
            raw_matches = self._rules.match(filepath=path, timeout=_SCAN_TIMEOUT_S)
        except yara.Error as exc:
            print(f"[Quarry] YARA: scan error on {path}: {exc}")
            return []
        except OSError:
            return []  # deleted/inaccessible between stat and match

        return [
            {"rule": m.rule, "tags": list(m.tags), "meta": dict(m.meta)}
            for m in raw_matches
        ]

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _compile_rules(self):
        if not self._rules_path:
            return None

        try:
            import yara
        except ImportError:
            print("[Quarry] YARA: yara-python not installed — YARA scanning disabled.")
            return None

        p = Path(self._rules_path)
        try:
            if p.is_dir():
                files = sorted(list(p.glob("*.yar")) + list(p.glob("*.yara")))
                if not files:
                    print(f"[Quarry] YARA: no .yar/.yara files found in {p} — disabled.")
                    return None
                filepaths = {f.stem: str(f) for f in files}
                rules = yara.compile(filepaths=filepaths)
            else:
                rules = yara.compile(filepath=str(p))
            print(f"[Quarry] YARA: rules loaded from {p}")
            return rules
        except yara.Error as exc:
            print(f"[Quarry] YARA: failed to compile rules from {p}: {exc} — disabled.")
            return None
        except OSError as exc:
            print(f"[Quarry] YARA: cannot read rules path {p}: {exc} — disabled.")
            return None

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _track_inflight(self, task: asyncio.Task) -> None:
        self._inflight.add(task)
        task.add_done_callback(self._inflight.discard)

    async def _shutdown_tasks(self) -> None:
        # _pending and _inflight overlap (a debounce task lives in both until it
        # completes) — dedupe via set so each task is cancelled/awaited once.
        tasks = set(self._pending.values()) | self._inflight
        self._pending.clear()
        self._inflight.clear()
        for t in tasks:
            t.cancel()
        for t in tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await t
