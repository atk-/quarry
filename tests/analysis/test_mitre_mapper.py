"""Tests for map_techniques()."""
from __future__ import annotations

from quarry.analysis.mitre_mapper import map_techniques
from quarry.models.event import (
    Event, EVENT_HOOK, EVENT_REGISTRY, EVENT_WMI, EVENT_POWERSHELL, EVENT_YARA,
)


def _hook(hook_name, pid=1234, **extra_data):
    return Event(event_type=EVENT_HOOK, pid=pid, data={"hook": hook_name, **extra_data})


def _registry(key, pid=1234):
    return Event(event_type=EVENT_REGISTRY, pid=pid, data={"op": "set_value", "key": key})


def test_injection_triad_maps_to_t1055():
    events = [
        _hook("VIRTUAL_ALLOC"),
        _hook("WRITE_PROCESS_MEMORY"),
        _hook("CREATE_REMOTE_THREAD"),
    ]
    matches = map_techniques(events)

    ids = [m.technique_id for m in matches]
    assert "T1055" in ids
    t1055 = next(m for m in matches if m.technique_id == "T1055")
    assert 1234 in t1055.pids
    assert t1055.evidence


def test_crypto_hooks_map_to_t1027():
    events = [_hook("CRYPT_ENCRYPT"), _hook("CRYPT_DECRYPT")]
    matches = map_techniques(events)
    assert any(m.technique_id == "T1027" for m in matches)


def test_registry_run_key_maps_to_t1547_001():
    events = [_registry(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")]
    matches = map_techniques(events)
    assert any(m.technique_id == "T1547.001" for m in matches)


def test_registry_winlogon_key_maps_to_t1547_004():
    events = [_registry(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")]
    matches = map_techniques(events)
    assert any(m.technique_id == "T1547.004" for m in matches)


def test_wmi_consumer_binding_maps_to_t1546_003():
    events = [Event(event_type=EVENT_WMI, pid=42, data={
        "op": "consumer_binding", "operation": "PutInstance __FilterToConsumerBinding",
    })]
    matches = map_techniques(events)
    assert any(m.technique_id == "T1546.003" for m in matches)


def test_powershell_event_maps_to_t1059_001():
    events = [Event(event_type=EVENT_POWERSHELL, pid=77, data={"script_text": "Get-Process"})]
    matches = map_techniques(events)
    assert any(m.technique_id == "T1059.001" for m in matches)


def test_yara_meta_technique_folds_into_existing_entry():
    events = [
        _hook("VIRTUAL_ALLOC"),
        _hook("WRITE_PROCESS_MEMORY"),
        _hook("CREATE_REMOTE_THREAD"),
        Event(event_type=EVENT_YARA, pid=1234, data={
            "path": "dropped.exe", "source": "file_write",
            "matches": [{"rule": "injector", "tags": [], "meta": {"mitre_technique": "T1055"}}],
        }),
    ]
    matches = map_techniques(events)

    t1055_matches = [m for m in matches if m.technique_id == "T1055"]
    assert len(t1055_matches) == 1
    assert len(t1055_matches[0].evidence) >= 2  # hook-derived + YARA-derived


def test_auto_inject_hook_alone_does_not_trigger_t1055():
    events = [_hook("AUTO_INJECT"), _hook("AUTO_INJECT_FAILED")]
    matches = map_techniques(events)
    assert not any(m.technique_id == "T1055" for m in matches)


def test_create_service_hook_and_services_registry_key_merge():
    events = [
        _hook("CREATE_SERVICE", pid=55),
        _registry(r"SYSTEM\CurrentControlSet\Services\\evilsvc", pid=55),
    ]
    matches = map_techniques(events)

    t1543_matches = [m for m in matches if m.technique_id == "T1543.003"]
    assert len(t1543_matches) == 1
    assert len(t1543_matches[0].evidence) == 2


def test_no_matching_events_returns_empty_list():
    events = [Event(event_type=EVENT_HOOK, pid=1, data={"hook": "INTERNET_CONNECT"})]
    assert map_techniques(events) == []
