"""
Central event bus for a Quarry session.

Events arrive from ETW callbacks (C threads) via the thread-safe post() method,
get written to SQLite, and are fanned out to any registered WebSocket subscribers.
"""
from __future__ import annotations
import asyncio
import json
import time
from collections import deque
from typing import Optional

import aiosqlite

from quarry.models.event import Event, EVENT_PROCESS
from quarry.models.process_tree import ProcessNode, ProcessTree

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY,
    timestamp    REAL    NOT NULL,
    pid          INTEGER NOT NULL DEFAULT 0,
    ppid         INTEGER NOT NULL DEFAULT 0,
    process_name TEXT    NOT NULL DEFAULT '',
    event_type   TEXT    NOT NULL,
    data         TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_pid  ON events(pid);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(timestamp);

CREATE TABLE IF NOT EXISTS processes (
    pid        INTEGER PRIMARY KEY,
    ppid       INTEGER NOT NULL DEFAULT 0,
    name       TEXT    NOT NULL DEFAULT '',
    image_path TEXT    NOT NULL DEFAULT '',
    cmdline    TEXT    NOT NULL DEFAULT '',
    start_time REAL,
    end_time   REAL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id        INTEGER PRIMARY KEY,
    kind      TEXT NOT NULL,
    timestamp REAL NOT NULL,
    data      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS static_analysis (
    id        INTEGER PRIMARY KEY,
    timestamp REAL NOT NULL,
    path      TEXT NOT NULL,
    data      TEXT NOT NULL
);
"""

_RECENT_CAP = 10_000
_SUB_CAP    = 1_000   # per-subscriber queue depth before dropping


class SessionStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._queue: asyncio.Queue[Event] = asyncio.Queue()
        self._recent: deque[Event] = deque(maxlen=_RECENT_CAP)
        self._subscribers: list[asyncio.Queue[Event]] = []
        self._tree = ProcessTree()
        self._db: Optional[aiosqlite.Connection] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def open(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._db = await aiosqlite.connect(self._db_path)
        await self._db.executescript(_SCHEMA)
        await self._db.commit()
        self._running = True

    async def close(self) -> None:
        self._running = False
        if self._db:
            await self._db.close()

    # ------------------------------------------------------------------
    # Ingestion — called from ETW callback threads
    # ------------------------------------------------------------------

    def post(self, event: Event) -> None:
        """Thread-safe: safe to call from any thread including C ETW callbacks."""
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, event)

    # ------------------------------------------------------------------
    # Drain loop — run as an asyncio task for the duration of the session
    # ------------------------------------------------------------------

    async def run(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            self._recent.append(event)
            self._update_tree(event)
            await self._persist(event)
            for sub in list(self._subscribers):
                try:
                    sub.put_nowait(event)
                except asyncio.QueueFull:
                    pass

    # ------------------------------------------------------------------
    # WebSocket fan-out
    # ------------------------------------------------------------------

    def subscribe(self) -> asyncio.Queue[Event]:
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=_SUB_CAP)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[Event]) -> None:
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def recent_events(self) -> list[Event]:
        return list(self._recent)

    @property
    def process_tree(self) -> ProcessTree:
        return self._tree

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    async def store_snapshot(self, kind: str, data: dict) -> None:
        if not self._db:
            return
        await self._db.execute(
            "INSERT INTO snapshots (kind, timestamp, data) VALUES (?, ?, ?)",
            (kind, time.time(), json.dumps(data)),
        )
        await self._db.commit()

    async def load_snapshot(self, kind: str) -> Optional[dict]:
        if not self._db:
            return None
        async with self._db.execute(
            "SELECT data FROM snapshots WHERE kind=? ORDER BY id DESC LIMIT 1", (kind,)
        ) as cur:
            row = await cur.fetchone()
            return json.loads(row[0]) if row else None

    # ------------------------------------------------------------------
    # Static analysis
    # ------------------------------------------------------------------

    async def store_static(self, analysis: dict) -> None:
        if not self._db:
            return
        await self._db.execute(
            "INSERT INTO static_analysis (timestamp, path, data) VALUES (?, ?, ?)",
            (time.time(), analysis.get("path", ""), json.dumps(analysis)),
        )
        await self._db.commit()

    async def load_static(self) -> Optional[dict]:
        if not self._db:
            return None
        async with self._db.execute(
            "SELECT data FROM static_analysis ORDER BY id DESC LIMIT 1"
        ) as cur:
            row = await cur.fetchone()
            return json.loads(row[0]) if row else None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _update_tree(self, event: Event) -> None:
        if event.event_type != EVENT_PROCESS:
            return
        sub = event.data.get("sub_type")
        if sub == "create":
            self._tree.add(ProcessNode(
                pid=event.pid,
                ppid=event.ppid,
                name=event.process_name,
                image_path=event.data.get("image_path", ""),
                cmdline=event.data.get("cmdline", ""),
                start_time=event.timestamp,
            ))
        elif sub == "exit":
            self._tree.terminate(event.pid, event.timestamp)

    async def _persist(self, event: Event) -> None:
        if not self._db:
            return
        await self._db.execute(
            "INSERT INTO events (timestamp, pid, ppid, process_name, event_type, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (event.timestamp, event.pid, event.ppid, event.process_name,
             event.event_type, json.dumps(event.data)),
        )
        if event.event_type == EVENT_PROCESS:
            sub = event.data.get("sub_type")
            if sub == "create":
                await self._db.execute(
                    "INSERT OR REPLACE INTO processes "
                    "(pid, ppid, name, image_path, cmdline, start_time) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (event.pid, event.ppid, event.process_name,
                     event.data.get("image_path", ""),
                     event.data.get("cmdline", ""),
                     event.timestamp),
                )
            elif sub == "exit":
                await self._db.execute(
                    "UPDATE processes SET end_time=? WHERE pid=?",
                    (event.timestamp, event.pid),
                )
        await self._db.commit()
