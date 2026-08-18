"""Tests for ETWSession._dispatch()'s translation of pywintrace's raw
(event_id, data) callback shape into the flat record dict every collector's
handle() expects.

This is a real-world regression test: _dispatch was never exercised outside
mock mode until live Windows testing, and the assumption that pywintrace
calls back with a ready-made flat dict (rather than a tuple with EventId/
ProcessId nested under "EventHeader") was wrong on both counts.
"""
from __future__ import annotations

from quarry.collectors.etw_session import ETWSession, _normalize_guid, _PROVIDER_GUIDS


def _make_session():
    return ETWSession(emit=lambda ev: None)


def _record(provider_name: str, event_id: int, process_id: int, **extra_fields):
    """Build a synthetic pywintrace-shaped (event_id, data) tuple."""
    guid = _PROVIDER_GUIDS[provider_name]
    return (event_id, {
        "EventHeader": {"ProviderId": guid, "ProcessId": process_id},
        **extra_fields,
    })


def test_dispatch_routes_to_correct_handler_by_guid():
    session = _make_session()
    received = []
    session.register_router("Microsoft-Windows-Kernel-Process", received.append)

    session._dispatch(_record(
        "Microsoft-Windows-Kernel-Process", event_id=1, process_id=4321,
        ImageFileName="evil.exe",
    ))

    assert len(received) == 1
    assert received[0]["EventId"] == 1
    assert received[0]["ProcessId"] == 4321
    assert received[0]["ImageFileName"] == "evil.exe"


def test_dispatch_does_not_cross_route_to_wrong_provider():
    session = _make_session()
    process_events = []
    file_events = []
    session.register_router("Microsoft-Windows-Kernel-Process", process_events.append)
    session.register_router("Microsoft-Windows-Kernel-File", file_events.append)

    session._dispatch(_record("Microsoft-Windows-Kernel-File", event_id=12, process_id=1))

    assert file_events and not process_events


def test_dispatch_unregistered_provider_is_silently_ignored():
    session = _make_session()
    received = []
    session.register_router("Microsoft-Windows-Kernel-Process", received.append)

    # WMI-Activity has no router registered in this test session.
    session._dispatch(_record("Microsoft-Windows-WMI-Activity", event_id=5861, process_id=1))

    assert received == []


def test_dispatch_matches_guid_regardless_of_braces_dashes_case():
    session = _make_session()
    received = []
    session.register_router("Microsoft-Windows-Kernel-Process", received.append)

    # Simulate ctypes' str(GUID) producing a differently-formatted (but
    # equivalent) string than our own bracketed literal.
    raw_guid = _PROVIDER_GUIDS["Microsoft-Windows-Kernel-Process"].strip("{}").lower()
    record = (2, {"EventHeader": {"ProviderId": raw_guid, "ProcessId": 99}})
    session._dispatch(record)

    assert len(received) == 1
    assert received[0]["ProcessId"] == 99


def test_normalize_guid_strips_formatting_and_uppercases():
    assert _normalize_guid("{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}") == \
        _normalize_guid("22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716")
