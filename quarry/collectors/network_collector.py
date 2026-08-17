"""
Collector: Microsoft-Windows-Kernel-Network + Microsoft-Windows-DNS-Client

Network events carry PID attribution directly in the kernel provider.
"""
from __future__ import annotations
from typing import Callable

from quarry.collectors.base import Collector
from quarry.models.event import Event, EVENT_NETWORK

PROVIDER_NET = "Microsoft-Windows-Kernel-Network"
PROVIDER_DNS = "Microsoft-Windows-DNS-Client"

PROVIDERS = [PROVIDER_NET, PROVIDER_DNS]

_EID_TCP_CONNECT    = 12
_EID_TCP_DISCONNECT = 13
_EID_TCP_SEND       = 10
_EID_TCP_RECEIVE    = 11
_EID_UDP_SEND       = 42
_EID_UDP_RECEIVE    = 43

_EID_DNS_QUERY    = 3008
_EID_DNS_RESPONSE = 3009


class NetworkCollector(Collector):
    PROVIDERS = PROVIDERS

    def __init__(self, emit: Callable[[Event], None]) -> None:
        super().__init__(emit)

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def handle_net(self, record: dict) -> None:
        eid = record.get("EventId", 0)
        pid = record.get("PID", 0)

        op_map = {
            _EID_TCP_CONNECT:    "tcp_connect",
            _EID_TCP_DISCONNECT: "tcp_disconnect",
            _EID_TCP_SEND:       "tcp_send",
            _EID_TCP_RECEIVE:    "tcp_recv",
            _EID_UDP_SEND:       "udp_send",
            _EID_UDP_RECEIVE:    "udp_recv",
        }
        op = op_map.get(eid)
        if op is None:
            return

        self._emit(Event(
            event_type=EVENT_NETWORK,
            pid=pid,
            data={
                "op":        op,
                "src_addr":  record.get("saddr", ""),
                "src_port":  record.get("sport", 0),
                "dst_addr":  record.get("daddr", ""),
                "dst_port":  record.get("dport", 0),
                "proto":     "tcp" if "tcp" in op else "udp",
                "bytes":     record.get("size", 0),
            },
        ))

    def handle_dns(self, record: dict) -> None:
        eid = record.get("EventId", 0)
        if eid not in (_EID_DNS_QUERY, _EID_DNS_RESPONSE):
            return
        self._emit(Event(
            event_type=EVENT_NETWORK,
            pid=record.get("ProcessID", 0),
            data={
                "op":       "dns_query" if eid == _EID_DNS_QUERY else "dns_response",
                "name":     record.get("QueryName", ""),
                "type":     record.get("QueryType", ""),
                "results":  record.get("QueryResults", ""),
            },
        ))
