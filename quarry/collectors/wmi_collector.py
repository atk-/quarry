"""Collector: Microsoft-Windows-WMI-Activity

WMI is a major fileless-execution and persistence vector: Win32_Process.Create
for remote/lateral-movement execution, and __EventFilter/__EventConsumer/
__FilterToConsumerBinding for persistence (event subscription backdoors that
survive reboots and are invisible to file/registry monitoring since they live
in the WMI repository). EventId 5861 (__FilterToConsumerBinding creation) is
the single highest-value signal this collector produces.

Each event carries a complete, independent operation record — unlike
PowerShellCollector, there is no cross-event fragment reassembly, so this
collector is stateless like RegistryCollector/FileCollector.

Note: EventId 5857 (Operation_Started) fires on essentially every WMI
operation system-wide, not scoped to the analyzed process — the same noise
characteristic Kernel-File/Kernel-Registry already have. The UI's existing
PID/type/text filters are the intended mitigation; this collector does not
suppress or rate-limit it.
"""
from __future__ import annotations
from typing import Callable

from quarry.collectors.base import Collector
from quarry.models.event import Event, EVENT_WMI

PROVIDER = "Microsoft-Windows-WMI-Activity"

_EID_OPERATION_STARTED       = 5857  # Operation_Started — every WMI op system-wide; noisy
_EID_CLIENT_FAILURE          = 5858  # Operation_ClientFailure
_EID_ESS_STARTED             = 5859  # Operation_EssStarted — permanent event subscription
_EID_TEMP_ESS_STARTED        = 5860  # Operation_TemporaryEssStarted
_EID_ESS_TO_CONSUMER_BINDING = 5861  # Operation_ESStoConsumerBinding — persistence signal

_OP_MAP = {
    _EID_OPERATION_STARTED:       "operation_started",
    _EID_CLIENT_FAILURE:          "client_failure",
    _EID_ESS_STARTED:             "event_subscription_started",
    _EID_TEMP_ESS_STARTED:        "temp_event_subscription_started",
    _EID_ESS_TO_CONSUMER_BINDING: "consumer_binding",
}


class WMIActivityCollector(Collector):
    PROVIDER = PROVIDER

    def __init__(self, emit: Callable[[Event], None]) -> None:
        super().__init__(emit)

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def handle(self, record: dict) -> None:
        eid = record.get("EventId", 0)
        op = _OP_MAP.get(eid)
        if op is None:
            return

        # NOTE: unlike most providers, the generic ETW-header ProcessId here
        # is the WMI host process (WmiPrvSE.exe), not the caller — prefer the
        # payload's ClientProcessId, which is the actual calling process.
        # Falls back to the header ProcessId only if ClientProcessId is
        # absent/zero (e.g. malformed or older-schema records).
        pid = record.get("ClientProcessId", 0) or record.get("ProcessId", 0)

        data = {
            "op":        op,
            "namespace": record.get("NamespaceName", "") or "",
            "operation": record.get("Operation", "") or "",
        }

        self._emit(Event(
            event_type=EVENT_WMI,
            pid=pid,
            data=data,
        ))
