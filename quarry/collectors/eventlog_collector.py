"""
Windows Event Log collector.

Reads from Security, System, and Application channels using the Windows
EvtSubscribe API (via pywin32). Falls back to a no-op on non-Windows.
"""
from __future__ import annotations
import sys
import threading
from typing import Callable, Optional

from quarry.collectors.base import Collector
from quarry.models.event import Event, EVENT_EVENTLOG

_WINDOWS = sys.platform == "win32"
_HAS_WIN32 = False

if _WINDOWS:
    try:
        import win32evtlog   # type: ignore[import]
        import win32con      # type: ignore[import]
        import win32event    # type: ignore[import]
        _HAS_WIN32 = True
    except ImportError:
        pass

_CHANNELS = ["Security", "System", "Application"]


class EventLogCollector(Collector):
    def __init__(self, emit: Callable[[Event], None]) -> None:
        super().__init__(emit)
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self._running = True
        if not _HAS_WIN32:
            return
        for channel in _CHANNELS:
            t = threading.Thread(
                target=self._subscribe, args=(channel,),
                daemon=True, name=f"evtlog-{channel}",
            )
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._running = False
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads.clear()

    def _subscribe(self, channel: str) -> None:
        # EvtSubscribe needs either a SignalEvent (pull mode, polled via
        # EvtNext below) or a Callback (push mode) to know which mode to
        # use — passing neither is rejected with ERROR_INVALID_PARAMETER (87).
        signal_event = win32event.CreateEvent(None, 0, 0, None)  # type: ignore[name-defined]
        handle = win32evtlog.EvtSubscribe(  # type: ignore[name-defined]
            channel,
            win32evtlog.EvtSubscribeToFutureEvents,  # type: ignore[name-defined]
            SignalEvent=signal_event,
        )
        while self._running:
            events = win32evtlog.EvtNext(handle, 10, 1000)  # type: ignore[name-defined]
            for ev in events:
                self._process(channel, ev)

    def _process(self, channel: str, ev) -> None:
        try:
            xml = win32evtlog.EvtRender(  # type: ignore[name-defined]
                ev, win32evtlog.EvtRenderEventXml  # type: ignore[name-defined]
            )
        except Exception:
            return
        self._emit(Event(
            event_type=EVENT_EVENTLOG,
            data={"channel": channel, "xml": xml},
        ))
