"""
IOC extractor — pulls indicators of compromise from the event stream.

Extracted: file paths, registry keys, IP addresses, domain names, file hashes.
Hashes are computed lazily if the file is accessible on disk.
"""
from __future__ import annotations
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from quarry.models.event import Event, EVENT_FILE, EVENT_REGISTRY, EVENT_NETWORK

_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|[a-z]{2})\b"
)


@dataclass
class IOCs:
    file_paths:     set[str] = field(default_factory=set)
    registry_keys:  set[str] = field(default_factory=set)
    ip_addresses:   set[str] = field(default_factory=set)
    domains:        set[str] = field(default_factory=set)
    file_hashes:    dict[str, str] = field(default_factory=dict)  # path -> sha256

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_paths":    sorted(self.file_paths),
            "registry_keys": sorted(self.registry_keys),
            "ip_addresses":  sorted(self.ip_addresses),
            "domains":       sorted(self.domains),
            "file_hashes":   self.file_hashes,
        }


def extract(events: list[Event], hash_files: bool = False) -> IOCs:
    iocs = IOCs()

    for ev in events:
        if ev.event_type == EVENT_FILE:
            path = ev.data.get("path", "")
            if path and _interesting_path(path):
                iocs.file_paths.add(path)
                if hash_files:
                    _try_hash(path, iocs)

        elif ev.event_type == EVENT_REGISTRY:
            key = ev.data.get("key", "")
            if key and _interesting_key(key):
                iocs.registry_keys.add(key)

        elif ev.event_type == EVENT_NETWORK:
            dst = ev.data.get("dst_addr", "")
            if dst:
                _classify_addr(dst, iocs)
            domain = ev.data.get("name", "")
            if domain and _looks_like_domain(domain):
                iocs.domains.add(domain.lower())

        # Sweep all string values for domains
        for v in ev.data.values():
            if isinstance(v, str):
                for m in _RE_DOMAIN.findall(v):
                    if _looks_like_domain(m):
                        iocs.domains.add(m.lower())

    return iocs


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

_NOISE_PREFIXES = (
    r"C:\Windows\System32\\",
    r"C:\Windows\SysWOW64\\",
    r"C:\Windows\WinSxS\\",
)
_INTERESTING_KEYS = (
    r"CurrentVersion\Run",
    r"CurrentVersion\RunOnce",
    r"CurrentVersion\Image File Execution Options",
    r"Winlogon",
    r"Services\\",
    r"AppInit_DLLs",
)


def _interesting_path(path: str) -> bool:
    return not any(path.startswith(p) for p in _NOISE_PREFIXES)


def _interesting_key(key: str) -> bool:
    return any(k in key for k in _INTERESTING_KEYS)


def _classify_addr(addr: str, iocs: IOCs) -> None:
    try:
        obj = ipaddress.ip_address(addr)
        if not obj.is_private and not obj.is_loopback:
            iocs.ip_addresses.add(addr)
    except ValueError:
        if _looks_like_domain(addr):
            iocs.domains.add(addr.lower())


def _looks_like_domain(s: str) -> bool:
    return bool(_RE_DOMAIN.match(s)) and len(s) > 4


def _try_hash(path: str, iocs: IOCs) -> None:
    try:
        data = Path(path).read_bytes()
        iocs.file_hashes[path] = hashlib.sha256(data).hexdigest()
    except OSError:
        pass
