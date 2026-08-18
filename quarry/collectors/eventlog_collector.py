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
        import pywintypes    # type: ignore[import]
        _HAS_WIN32 = True
    except ImportError:
        pass

# Win32 system error codes EvtNext can surface — see _subscribe().
_ERROR_NO_MORE_ITEMS = 259
_ERROR_INVALID_OPERATION = 4317

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
        # Manual-reset, initially-signaled, matching Microsoft's documented
        # pull-subscription pattern ("Subscribing to Events" on MSDN): wait
        # for the signal, drain with EvtNext until ERROR_NO_MORE_ITEMS, reset
        # the event, wait again. Calling EvtNext without waiting on the
        # signal first (the original bug here) can raise
        # ERROR_INVALID_OPERATION (4317) instead of just returning no events.
        signal_event = win32event.CreateEvent(None, 1, 1, None)  # type: ignore[name-defined]
        handle = win32evtlog.EvtSubscribe(  # type: ignore[name-defined]
            channel,
            win32evtlog.EvtSubscribeToFutureEvents,  # type: ignore[name-defined]
            SignalEvent=signal_event,
        )
        while self._running:
            wait_result = win32event.WaitForSingleObject(signal_event, 1000)  # type: ignore[name-defined]
            if wait_result != 0:  # WAIT_OBJECT_0 — timed out, just re-check self._running
                continue

            while True:
                try:
                    events = win32evtlog.EvtNext(handle, 10, 0)  # type: ignore[name-defined]
                except pywintypes.error as exc:  # type: ignore[name-defined]
                    # ERROR_NO_MORE_ITEMS: fully drained, go back to waiting.
                    # ERROR_INVALID_OPERATION: pywin32's own EvtNext wrapper
                    # is supposed to swallow this into an empty result when
                    # it means "nothing available," but a known wrapper bug
                    # (mhammond/pywin32#2377) can let it leak through as an
                    # exception instead — treat it the same way.
                    if exc.winerror in (_ERROR_NO_MORE_ITEMS, _ERROR_INVALID_OPERATION):
                        break
                    raise
                if not events:
                    break
                for ev in events:
                    self._process(channel, ev)

            win32event.ResetEvent(signal_event)  # type: ignore[name-defined]

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
