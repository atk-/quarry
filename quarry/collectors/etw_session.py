"""
ETW real-time session manager.

Runs a single ETW session covering all configured providers. Each provider's
events are routed to the appropriate per-domain handler via register_router().

Requires admin privileges on Windows. On non-Windows environments the session
emits synthetic process events so the full pipeline can be exercised during dev.

pywintrace is the ETW binding (pip install pywintrace). If unavailable, the
mock generator is used regardless of platform.
"""
from __future__ import annotations
import random
import sys
import threading
import time
from typing import Callable, Optional

from quarry.models.event import Event, EVENT_PROCESS

# Providers that the session will subscribe to. All are modern (Windows 8+)
# non-kernel-logger providers, so they work without a special session name.
ETW_PROVIDERS = [
    "Microsoft-Windows-Kernel-Process",
    "Microsoft-Windows-Kernel-File",
    "Microsoft-Windows-Kernel-Registry",
    "Microsoft-Windows-Kernel-Network",
    "Microsoft-Windows-DNS-Client",
    "Microsoft-Windows-PowerShell",
    "Microsoft-Windows-DotNETRuntime",
    "Microsoft-Windows-WMI-Activity",
    "Microsoft-Windows-TaskScheduler",
    "Microsoft-Antimalware-Engine",
]

# ETW providers are addressed by GUID, not name — pywintrace's ProviderInfo
# requires one. Every name in ETW_PROVIDERS must have an entry here.
_PROVIDER_GUIDS = {
    "Microsoft-Windows-Kernel-Process":  "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
    "Microsoft-Windows-Kernel-File":     "{EDD08927-9CC4-4E65-B970-C2560FB5C289}",
    "Microsoft-Windows-Kernel-Registry": "{70EB4F03-C1DE-4F73-A051-33D13D5413BD}",
    "Microsoft-Windows-Kernel-Network":  "{7DD42A49-5329-4832-8DFD-43D979153A88}",
    "Microsoft-Windows-DNS-Client":      "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}",
    "Microsoft-Windows-PowerShell":      "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
    "Microsoft-Windows-DotNETRuntime":   "{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}",
    "Microsoft-Windows-WMI-Activity":    "{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}",
    "Microsoft-Windows-TaskScheduler":   "{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}",
    "Microsoft-Antimalware-Engine":      "{0A002690-3839-4E3A-B3B6-96D8DF868D99}",
}

_WINDOWS = sys.platform == "win32"
_HAS_ETW = False

if _WINDOWS:
    try:
        from etw import ETW, ProviderInfo, GUID  # type: ignore[import]
        _HAS_ETW = True
    except ImportError:
        pass


class ETWSession:
    """
    Manages a single real-time ETW session.

    Routers registered via register_router() receive raw event record dicts
    keyed by provider name. Handlers run in the ETW callback thread — they
    should be short and non-blocking; post to asyncio queue via emit().
    """

    def __init__(self, emit: Callable[[Event], None]) -> None:
        self._emit = emit
        self._routers: dict[str, Callable[[dict], None]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._session = None

    def register_router(self, provider: str, handler: Callable[[dict], None]) -> None:
        self._routers[provider] = handler

    def start(self) -> None:
        self._running = True
        if _HAS_ETW:
            self._start_real()
        else:
            self._thread = threading.Thread(
                target=self._mock_loop, daemon=True, name="etw-mock"
            )
            self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._session is not None:
            try:
                self._session.stop()
            except Exception:
                pass
            self._session = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    # ------------------------------------------------------------------
    # Real ETW path
    # ------------------------------------------------------------------

    def _start_real(self) -> None:
        providers = []
        for name in ETW_PROVIDERS:
            guid = _PROVIDER_GUIDS.get(name)
            if guid is None:
                print(f"[Quarry] ETW: no GUID registered for provider {name!r} — skipping.")
                continue
            providers.append(
                ProviderInfo(name, GUID(guid), level=5)  # type: ignore[name-defined]
            )
        self._session = ETW(  # type: ignore[name-defined]
            providers=providers,
            event_callback=self._dispatch,
        )
        self._thread = threading.Thread(
            target=self._session.start, daemon=True, name="etw-real"
        )
        self._thread.start()

    def _dispatch(self, record: dict) -> None:
        provider = record.get("ProviderName", "")
        handler = self._routers.get(provider)
        if handler is not None:
            handler(record)

    # ------------------------------------------------------------------
    # Mock path for offline dev
    # ------------------------------------------------------------------

    _MOCK_PROCS = [
        ("explorer.exe", 4, r"C:\Windows\explorer.exe"),
        ("svchost.exe",  4, r"C:\Windows\System32\svchost.exe"),
        ("lsass.exe",    4, r"C:\Windows\System32\lsass.exe"),
    ]
    _MOCK_SPAWNS = [
        ("notepad.exe",     r"C:\Windows\System32\notepad.exe"),
        ("cmd.exe",         r"C:\Windows\System32\cmd.exe"),
        ("powershell.exe",  r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        ("regsvr32.exe",    r"C:\Windows\System32\regsvr32.exe"),
        ("rundll32.exe",    r"C:\Windows\System32\rundll32.exe"),
    ]

    def _mock_loop(self) -> None:
        pid_counter = 1000
        # seed with root processes
        for name, ppid, path in self._MOCK_PROCS:
            pid_counter += 1
            self._emit(Event(
                event_type=EVENT_PROCESS,
                pid=pid_counter,
                ppid=ppid,
                process_name=name,
                data={"sub_type": "create", "image_path": path, "cmdline": name},
            ))
        live_pids = list(range(1001, pid_counter + 1))

        while self._running:
            time.sleep(random.uniform(0.3, 1.2))
            roll = random.random()
            if roll < 0.5:
                name, path = random.choice(self._MOCK_SPAWNS)
                pid_counter += 1
                ppid = random.choice(live_pids) if live_pids else 4
                self._emit(Event(
                    event_type=EVENT_PROCESS,
                    pid=pid_counter,
                    ppid=ppid,
                    process_name=name,
                    data={"sub_type": "create", "image_path": path,
                          "cmdline": f"{name} /mock-arg"},
                ))
                live_pids.append(pid_counter)
            elif roll < 0.7 and live_pids:
                victim = random.choice(live_pids)
                live_pids.remove(victim)
                self._emit(Event(
                    event_type=EVENT_PROCESS,
                    pid=victim,
                    data={"sub_type": "exit", "exit_code": 0},
                ))
