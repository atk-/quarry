"""Tests for WMIActivityCollector's EventId mapping and PID attribution."""
from __future__ import annotations

from quarry.collectors.wmi_collector import WMIActivityCollector
from quarry.models.event import EVENT_WMI


def _make_collector():
    emitted: list = []
    collector = WMIActivityCollector(emit=emitted.append)
    return collector, emitted


def _rec(eid, namespace="root\\cimv2", operation="", client_pid=0, pid=0,
         omit_client_pid=False, omit_namespace=False, omit_operation=False):
    record = {"EventId": eid}
    if not omit_namespace:
        record["NamespaceName"] = namespace
    if not omit_operation:
        record["Operation"] = operation
    if not omit_client_pid:
        record["ClientProcessId"] = client_pid
    record["ProcessId"] = pid
    return record


def test_operation_started_5857():
    collector, emitted = _make_collector()
    collector.handle(_rec(5857, operation="Start IWbemServices::ExecQuery - root\\cimv2 : SELECT * FROM Win32_Process"))

    assert len(emitted) == 1
    ev = emitted[0]
    assert ev.event_type == EVENT_WMI
    assert ev.data["op"] == "operation_started"
    assert ev.data["namespace"] == "root\\cimv2"
    assert "ExecQuery" in ev.data["operation"]


def test_client_failure_5858():
    collector, emitted = _make_collector()
    collector.handle(_rec(5858))
    assert emitted[0].data["op"] == "client_failure"


def test_ess_started_5859():
    collector, emitted = _make_collector()
    collector.handle(_rec(5859))
    assert emitted[0].data["op"] == "event_subscription_started"


def test_temp_ess_started_5860():
    collector, emitted = _make_collector()
    collector.handle(_rec(5860))
    assert emitted[0].data["op"] == "temp_event_subscription_started"


def test_consumer_binding_5861():
    collector, emitted = _make_collector()
    operation = ("Start IWbemServices::PutInstance - root\\subscription : "
                 "__FilterToConsumerBinding")
    collector.handle(_rec(5861, namespace="root\\subscription", operation=operation))

    ev = emitted[0]
    assert ev.data["op"] == "consumer_binding"
    assert ev.data["namespace"] == "root\\subscription"
    assert ev.data["operation"] == operation


def test_client_process_id_preferred_when_present():
    collector, emitted = _make_collector()
    collector.handle(_rec(5857, client_pid=4321, pid=999))
    assert emitted[0].pid == 4321


def test_falls_back_to_process_id_when_client_process_id_absent():
    collector, emitted = _make_collector()
    collector.handle(_rec(5857, pid=999, omit_client_pid=True))
    assert emitted[0].pid == 999


def test_falls_back_to_process_id_when_client_process_id_zero():
    collector, emitted = _make_collector()
    collector.handle(_rec(5857, client_pid=0, pid=999))
    assert emitted[0].pid == 999


def test_unknown_event_id_is_ignored():
    collector, emitted = _make_collector()
    collector.handle(_rec(9999))
    assert emitted == []


def test_missing_namespace_and_operation_default_to_empty_string():
    collector, emitted = _make_collector()
    collector.handle(_rec(5857, omit_namespace=True, omit_operation=True))

    ev = emitted[0]
    assert ev.data["namespace"] == ""
    assert ev.data["operation"] == ""
