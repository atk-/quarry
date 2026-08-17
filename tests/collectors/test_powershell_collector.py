"""Tests for PowerShellCollector's EID 4104 fragment reassembly."""
from __future__ import annotations

from quarry.collectors.powershell_collector import (
    PowerShellCollector, _MAX_TRACKED_BLOCKS, _MAX_SCRIPT_TEXT_LEN,
)
from quarry.models.event import EVENT_POWERSHELL


def _make_collector():
    emitted: list = []
    collector = PowerShellCollector(emit=emitted.append)
    return collector, emitted


def _frag(block_id, num, total, text, path="", pid=1234):
    return {
        "EventId": 4104,
        "ScriptBlockId": block_id,
        "MessageNumber": num,
        "MessageTotal": total,
        "ScriptBlockText": text,
        "Path": path,
        "ProcessId": pid,
    }


def test_single_fragment_emits_immediately():
    collector, emitted = _make_collector()
    collector.handle(_frag("abc-1", 1, 1, "Get-Process", path=r"C:\evil.ps1"))

    assert len(emitted) == 1
    ev = emitted[0]
    assert ev.event_type == EVENT_POWERSHELL
    assert ev.pid == 1234
    assert ev.data["script_block_id"] == "abc-1"
    assert ev.data["path"] == r"C:\evil.ps1"
    assert ev.data["script_text"] == "Get-Process"
    assert ev.data["message_total"] == 1
    assert ev.data["truncated"] is False


def test_multi_fragment_in_order_joins_correctly():
    collector, emitted = _make_collector()
    collector.handle(_frag("bid-2", 1, 3, "Invoke-"))
    collector.handle(_frag("bid-2", 2, 3, "Expression "))
    assert emitted == []  # still incomplete

    collector.handle(_frag("bid-2", 3, 3, "$x"))
    assert len(emitted) == 1
    assert emitted[0].data["script_text"] == "Invoke-Expression $x"


def test_multi_fragment_out_of_order_still_joins_correctly():
    collector, emitted = _make_collector()
    collector.handle(_frag("bid-3", 3, 3, "$x"))
    collector.handle(_frag("bid-3", 1, 3, "Invoke-"))
    collector.handle(_frag("bid-3", 2, 3, "Expression "))

    assert len(emitted) == 1
    assert emitted[0].data["script_text"] == "Invoke-Expression $x"


def test_incomplete_block_does_not_emit_and_buffer_retains_state():
    collector, emitted = _make_collector()
    collector.handle(_frag("bid-4", 1, 5, "partial"))

    assert emitted == []
    assert "bid-4" in collector._buffers
    assert collector._buffers["bid-4"]["parts"][1] == "partial"


def test_buffer_eviction_drops_oldest_incomplete_block():
    collector, emitted = _make_collector()
    for i in range(_MAX_TRACKED_BLOCKS):
        collector.handle(_frag(f"bid-{i}", 1, 2, "chunk"))  # each incomplete (total=2)
    assert len(collector._buffers) == _MAX_TRACKED_BLOCKS
    assert "bid-0" in collector._buffers

    collector.handle(_frag("bid-new", 1, 2, "chunk"))  # exceeds cap, triggers eviction

    assert len(collector._buffers) == _MAX_TRACKED_BLOCKS
    assert "bid-0" not in collector._buffers      # oldest evicted
    assert "bid-new" in collector._buffers        # newest retained
    assert emitted == []                            # eviction isn't an emit


def test_oversized_script_text_is_truncated():
    collector, emitted = _make_collector()
    big_text = "A" * (_MAX_SCRIPT_TEXT_LEN + 500)
    collector.handle(_frag("bid-big", 1, 1, big_text))

    assert len(emitted) == 1
    ev = emitted[0]
    assert ev.data["truncated"] is True
    assert len(ev.data["script_text"]) == _MAX_SCRIPT_TEXT_LEN


def test_non_4104_event_is_ignored():
    collector, emitted = _make_collector()
    collector.handle({
        "EventId": 4103,  # "Executing Pipeline" — not script block logging
        "ScriptBlockId": "should-be-ignored",
        "ProcessId": 1234,
    })

    assert emitted == []
    assert collector._buffers == {}
