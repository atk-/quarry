"""Tests for FileCollector's PID attribution.

Regression coverage for a bug where file events were tagged with the ETW
record's IssuingThreadId (a thread ID) instead of ProcessId, breaking
per-PID correlation (process tree, UI PID filter, correlator grouping).
"""
from __future__ import annotations

from quarry.collectors.file_collector import FileCollector
from quarry.models.event import EVENT_FILE


def _make_collector():
    emitted: list = []
    collector = FileCollector(emit=emitted.append)
    return collector, emitted


def test_create_event_uses_process_id_not_thread_id():
    collector, emitted = _make_collector()

    collector.handle({
        "EventId": 12,  # create
        "FileName": r"C:\Users\victim\Desktop\evil.exe",
        "ProcessId": 4321,
        "IssuingThreadId": 9999,
    })

    assert len(emitted) == 1
    event = emitted[0]
    assert event.event_type == EVENT_FILE
    assert event.pid == 4321
    assert event.data["tid"] == 9999
    assert event.data["op"] == "create"
    assert event.data["path"] == r"C:\Users\victim\Desktop\evil.exe"


def test_write_event_includes_byte_count():
    collector, emitted = _make_collector()

    collector.handle({
        "EventId": 16,  # write
        "FileName": r"C:\Users\victim\dropped.dll",
        "ProcessId": 111,
        "IssuingThreadId": 222,
        "IoSize": 4096,
    })

    event = emitted[0]
    assert event.pid == 111
    assert event.data["op"] == "write"
    assert event.data["bytes"] == 4096


def test_rename_event_includes_new_path():
    collector, emitted = _make_collector()

    collector.handle({
        "EventId": 10,  # rename
        "FileName": r"C:\Users\victim\tmp123.tmp",
        "NewFileName": r"C:\Users\victim\payload.exe",
        "ProcessId": 555,
        "IssuingThreadId": 666,
    })

    event = emitted[0]
    assert event.pid == 555
    assert event.data["op"] == "rename"
    assert event.data["new_path"] == r"C:\Users\victim\payload.exe"


def test_unknown_event_id_is_ignored():
    collector, emitted = _make_collector()

    collector.handle({
        "EventId": 999,
        "FileName": "irrelevant",
        "ProcessId": 1,
        "IssuingThreadId": 2,
    })

    assert emitted == []
