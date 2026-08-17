"""Tests for YaraScanner: rule compilation, debounced file-write scanning,
immediate mem-dump scanning, and graceful degradation.

Uses the real `yara` module (a base dependency, not Windows-gated) against
real temp files — only the debounce timing is sped up via monkeypatching.
"""
from __future__ import annotations
import asyncio
import contextlib
from pathlib import Path

import pytest

import quarry.analysis.yara_scanner as yara_scanner_mod
from quarry.analysis.yara_scanner import YaraScanner
from quarry.models.event import Event, EVENT_FILE, EVENT_HOOK, EVENT_YARA


class _FakeStore:
    def __init__(self) -> None:
        self.posted: list[Event] = []
        self.queue: asyncio.Queue = asyncio.Queue()
        self.subscribed = False

    def subscribe(self) -> asyncio.Queue:
        self.subscribed = True
        return self.queue

    def unsubscribe(self, q: asyncio.Queue) -> None:
        pass

    def post(self, event: Event) -> None:
        self.posted.append(event)


class _RunningScanner:
    """Runs a YaraScanner as a background task and tears it down cleanly."""

    def __init__(self, scanner: YaraScanner) -> None:
        self.scanner = scanner
        self.task: asyncio.Task | None = None

    async def __aenter__(self) -> "_RunningScanner":
        self.task = asyncio.create_task(self.scanner.run())
        await asyncio.sleep(0.05)  # let run() compile rules + subscribe
        return self

    async def __aexit__(self, *exc) -> None:
        self.scanner.stop()
        self.task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self.task


@pytest.fixture()
def fast_debounce(monkeypatch):
    """Shrink the write-debounce window so tests don't wait 500ms each."""
    monkeypatch.setattr(yara_scanner_mod, "_DEBOUNCE_DELAY", 0.02)


_MATCH_RULE = 'rule quarry_test_rule { strings: $a = "QUARRY_TEST_MARKER" condition: $a }'
_NOMATCH_RULE = 'rule quarry_never { strings: $a = "THIS_NEVER_APPEARS_XYZ" condition: $a }'


def _write_rule_file(tmp_path: Path, source: str, name: str = "rules.yar") -> Path:
    p = tmp_path / name
    p.write_text(source)
    return p


async def test_file_write_triggers_scan_and_match_event(tmp_path, fast_debounce):
    rules_file = _write_rule_file(tmp_path, _MATCH_RULE)
    target = tmp_path / "dropped.exe"
    target.write_text("hello QUARRY_TEST_MARKER world")

    store = _FakeStore()
    scanner = YaraScanner(rules_path=str(rules_file), store=store)
    async with _RunningScanner(scanner):
        store.queue.put_nowait(Event(
            event_type=EVENT_FILE, pid=1234,
            data={"op": "write", "path": str(target)},
        ))
        await asyncio.sleep(0.2)  # debounce (0.02) + scan

    assert len(store.posted) == 1
    event = store.posted[0]
    assert event.event_type == EVENT_YARA
    assert event.pid == 1234
    assert event.data["source"] == "file_write"
    assert event.data["path"] == str(target)
    assert event.data["matches"][0]["rule"] == "quarry_test_rule"


async def test_mem_dump_triggers_immediate_scan(tmp_path):
    # deliberately not using fast_debounce — proves the mem-dump path doesn't
    # wait for the (real, 0.5s) write-debounce window at all.
    rules_file = _write_rule_file(tmp_path, _MATCH_RULE)
    dump = tmp_path / "dump.bin"
    dump.write_text("QUARRY_TEST_MARKER")

    store = _FakeStore()
    scanner = YaraScanner(rules_path=str(rules_file), store=store)
    async with _RunningScanner(scanner):
        store.queue.put_nowait(Event(
            event_type=EVENT_HOOK, pid=99,
            data={"hook": "MEM_DUMP", "dump_path": str(dump)},
        ))
        await asyncio.sleep(0.15)

    assert len(store.posted) == 1
    event = store.posted[0]
    assert event.data["source"] == "mem_dump"
    assert event.pid == 99


async def test_no_match_posts_nothing(tmp_path, fast_debounce):
    rules_file = _write_rule_file(tmp_path, _NOMATCH_RULE)
    target = tmp_path / "benign.txt"
    target.write_text("just some normal content")

    store = _FakeStore()
    scanner = YaraScanner(rules_path=str(rules_file), store=store)
    async with _RunningScanner(scanner):
        store.queue.put_nowait(Event(
            event_type=EVENT_FILE, pid=1,
            data={"op": "write", "path": str(target)},
        ))
        await asyncio.sleep(0.1)

    assert store.posted == []


async def test_rapid_writes_debounce_to_single_scan(tmp_path, fast_debounce):
    rules_file = _write_rule_file(tmp_path, _MATCH_RULE)
    target = tmp_path / "dropped.exe"
    target.write_text("QUARRY_TEST_MARKER")

    store = _FakeStore()
    scanner = YaraScanner(rules_path=str(rules_file), store=store)

    call_count = 0
    original_do_scan = scanner._do_scan

    def counting_do_scan(path):
        nonlocal call_count
        call_count += 1
        return original_do_scan(path)

    scanner._do_scan = counting_do_scan

    async with _RunningScanner(scanner):
        for _ in range(5):
            store.queue.put_nowait(Event(
                event_type=EVENT_FILE, pid=1,
                data={"op": "write", "path": str(target)},
            ))
            await asyncio.sleep(0.005)  # well under debounce (0.02) — cancels+reschedules
        await asyncio.sleep(0.2)

    assert call_count == 1
    assert len(store.posted) == 1


async def test_no_rules_run_does_not_subscribe():
    store = _FakeStore()
    scanner = YaraScanner(rules_path=None, store=store)
    await scanner.run()  # returns immediately — no rules to load
    assert store.subscribed is False


async def test_compile_failure_disables_scanner(tmp_path):
    bad_rules = tmp_path / "bad.yar"
    bad_rules.write_text("this is not valid yara syntax {{{")

    store = _FakeStore()
    scanner = YaraScanner(rules_path=str(bad_rules), store=store)
    await scanner.run()
    assert store.subscribed is False


async def test_missing_file_handled_gracefully(tmp_path, fast_debounce):
    rules_file = _write_rule_file(tmp_path, _MATCH_RULE)
    missing = tmp_path / "does_not_exist.exe"

    store = _FakeStore()
    scanner = YaraScanner(rules_path=str(rules_file), store=store)
    async with _RunningScanner(scanner):
        store.queue.put_nowait(Event(
            event_type=EVENT_FILE, pid=1,
            data={"op": "write", "path": str(missing)},
        ))
        await asyncio.sleep(0.1)

    assert store.posted == []


async def test_oversized_file_skipped(tmp_path, fast_debounce, monkeypatch):
    monkeypatch.setattr(yara_scanner_mod, "_MAX_SCAN_BYTES", 10)
    rules_file = _write_rule_file(tmp_path, _MATCH_RULE)
    target = tmp_path / "big.bin"
    target.write_text("QUARRY_TEST_MARKER" * 10)  # well over the 10-byte cap

    store = _FakeStore()
    scanner = YaraScanner(rules_path=str(rules_file), store=store)
    async with _RunningScanner(scanner):
        store.queue.put_nowait(Event(
            event_type=EVENT_FILE, pid=1,
            data={"op": "write", "path": str(target)},
        ))
        await asyncio.sleep(0.1)

    assert store.posted == []
