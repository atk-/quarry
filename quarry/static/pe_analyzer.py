"""
PE static analysis module.

Returns a plain dict so results can be stored directly in SQLite and served
via JSON without any serialization layer. Always returns a dict; check the
'error' key to detect parse failures.

Requires: pefile (pip install pefile) — pure Python, cross-platform.
"""
from __future__ import annotations

import hashlib
import math
import re
import time
from pathlib import Path
from typing import Any

try:
    import pefile          # type: ignore[import]
    _HAS_PEFILE = True
except ImportError:
    _HAS_PEFILE = False


# ── Constants ────────────────────────────────────────────────────────

_MACHINE = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x0200: "IA64",
}

_SUBSYSTEM = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    14: "Xbox",
    16: "Windows Boot Application",
}

_SECTION_FLAGS = [
    (0x00000020, "CODE"),
    (0x00000040, "IDATA"),
    (0x00000080, "UDATA"),
    (0x20000000, "X"),
    (0x40000000, "R"),
    (0x80000000, "W"),
]

# APIs that are meaningfully suspicious in combination or isolation
_SUSPICIOUS_IMPORTS: set[str] = {
    # Process / memory injection
    "VirtualAllocEx", "VirtualAlloc", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "NtCreateThreadEx", "RtlCreateUserThread",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "NtMapViewOfSection", "NtCreateSection",
    # Hook-based injection
    "SetWindowsHookExA", "SetWindowsHookExW",
    "QueueUserAPC", "NtQueueApcThread",
    # Anti-debug / evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugStringA",
    "FindWindowA", "FindWindowW",
    # Persistence
    "RegSetValueExA", "RegSetValueExW",
    "RegCreateKeyExA", "RegCreateKeyExW",
    "CreateServiceA", "CreateServiceW",
    "ChangeServiceConfigA", "ChangeServiceConfigW",
    # Download / network
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW",
    "InternetConnectA", "InternetConnectW",
    "HttpOpenRequestA", "HttpOpenRequestW",
    "HttpSendRequestA", "HttpSendRequestW",
    "WSAStartup",
    # Shellcode staples
    "LoadLibraryA", "LoadLibraryW",
    "GetProcAddress",
    # Crypto
    "CryptEncrypt", "CryptDecrypt",
    "BCryptEncrypt", "BCryptDecrypt",
}

# Packer detection: section name → packer label
_PACKER_SECTIONS: dict[str, str] = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".nsp0": "NSPack", ".nsp1": "NSPack", ".nsp2": "NSPack",
    ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    ".petite": "Petite",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".perplex": "Perplex",
    "PELOCKnt": "PELock",
    ".themida": "Themida/WinLicense",
    ".winlice": "Themida/WinLicense",
}

_MIN_STR_LEN   = 5
_MAX_ASCII_STR = 500
_MAX_UNI_STR   = 200
_HIGH_ENTROPY  = 7.0
_VERY_HIGH_ENT = 7.5


# ── Public entry point ───────────────────────────────────────────────

def analyze(path: str | Path) -> dict[str, Any]:
    """
    Analyze a PE file. Returns a plain dict suitable for JSON serialisation.
    On any fatal error the dict still contains identity fields plus 'error'.
    """
    path = Path(path)
    raw  = _read_file(path)
    if raw is None:
        return {"path": str(path), "error": f"Cannot read file: {path}"}

    result: dict[str, Any] = {
        "path":       str(path),
        "file_size":  len(raw),
        "sha256":     hashlib.sha256(raw).hexdigest(),
        "md5":        hashlib.md5(raw).hexdigest(),  # noqa: S324 — used for file ID, not security
        "error":      None,
    }

    if not _HAS_PEFILE:
        result["error"] = "pefile not installed (pip install pefile)"
        return result

    try:
        pe = pefile.PE(data=raw, fast_load=False)
    except pefile.PEFormatError as exc:
        result["error"] = f"Not a valid PE: {exc}"
        _add_strings(result, raw)
        return result

    try:
        _add_header(result, pe)
        _add_sections(result, pe, raw)
        _add_imports(result, pe)
        _add_exports(result, pe)
        _add_overlay(result, pe, raw)
        _add_strings(result, raw)
        _add_packer_clues(result, pe)
        _add_anomalies(result, pe, raw)
        _score(result)
    except Exception as exc:
        result["error"] = f"Partial parse error: {exc}"
        result.setdefault("risk_score", 0)
        result.setdefault("risk_indicators", [])

    return result


# ── Header ───────────────────────────────────────────────────────────

def _add_header(r: dict, pe: "pefile.PE") -> None:
    fh  = pe.FILE_HEADER
    oh  = pe.OPTIONAL_HEADER
    ts  = fh.TimeDateStamp
    r["machine"]             = _MACHINE.get(fh.Machine, f"0x{fh.Machine:04X}")
    r["is_64bit"]            = isinstance(oh, pefile.Structure) and oh.Magic == 0x20B
    r["is_dll"]              = bool(fh.Characteristics & 0x2000)
    r["compile_timestamp"]   = ts
    r["compile_timestamp_str"] = (
        time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))
        if 0 < ts < 0xFFFFFFFF else "invalid"
    )
    r["subsystem"]           = _SUBSYSTEM.get(oh.Subsystem, f"0x{oh.Subsystem:04X}")
    r["entry_point"]         = oh.AddressOfEntryPoint
    r["image_base"]          = oh.ImageBase
    r["image_size"]          = oh.SizeOfImage
    r["num_sections"]        = fh.NumberOfSections
    r["characteristics"]     = f"0x{fh.Characteristics:04X}"


# ── Sections ─────────────────────────────────────────────────────────

def _add_sections(r: dict, pe: "pefile.PE", raw: bytes) -> None:
    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        data = s.get_data()
        ent  = _entropy(data)
        flags = " ".join(f for mask, f in _SECTION_FLAGS if s.Characteristics & mask)
        sections.append({
            "name":            name,
            "virtual_address": s.VirtualAddress,
            "virtual_size":    s.Misc_VirtualSize,
            "raw_size":        s.SizeOfRawData,
            "entropy":         round(ent, 3),
            "characteristics": flags,
            "md5":             hashlib.md5(data).hexdigest(),  # noqa: S324
        })
    r["sections"] = sections
    r["overall_entropy"] = round(_entropy(raw), 3)


# ── Imports ──────────────────────────────────────────────────────────

def _add_imports(r: dict, pe: "pefile.PE") -> None:
    imports = []
    suspicious: list[str] = []

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        r["imports"]           = []
        r["suspicious_imports"] = []
        return

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll  = entry.dll.decode("ascii", errors="replace") if entry.dll else "?"
        fns  = []
        susp = []
        for imp in entry.imports:
            name = imp.name.decode("ascii", errors="replace") if imp.name else f"ord({imp.ordinal})"
            fns.append(name)
            if name in _SUSPICIOUS_IMPORTS:
                susp.append(name)
                if name not in suspicious:
                    suspicious.append(name)
        imports.append({"dll": dll, "functions": fns, "suspicious": susp})

    r["imports"]            = imports
    r["suspicious_imports"] = suspicious


# ── Exports ──────────────────────────────────────────────────────────

def _add_exports(r: dict, pe: "pefile.PE") -> None:
    exports: list[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("ascii", errors="replace") if exp.name else f"ord({exp.ordinal})"
            exports.append(name)
    r["exports"] = exports


# ── Overlay ──────────────────────────────────────────────────────────

def _add_overlay(r: dict, pe: "pefile.PE", raw: bytes) -> None:
    overlay_off = pe.get_overlay_data_start_offset()
    if overlay_off and overlay_off < len(raw):
        r["has_overlay"]   = True
        r["overlay_size"]  = len(raw) - overlay_off
        r["overlay_entropy"] = round(_entropy(raw[overlay_off:]), 3)
    else:
        r["has_overlay"]   = False
        r["overlay_size"]  = 0
        r["overlay_entropy"] = 0.0


# ── Strings ──────────────────────────────────────────────────────────

def _add_strings(r: dict, raw: bytes) -> None:
    ascii_pat = re.compile(rb"[\x20-\x7E]{" + str(_MIN_STR_LEN).encode() + rb",}")
    uni_pat   = re.compile(
        rb"(?:[\x20-\x7E]\x00){" + str(_MIN_STR_LEN).encode() + rb",}"
    )
    ascii_strs = [m.group().decode("ascii") for m in ascii_pat.finditer(raw)]
    uni_strs   = [
        m.group().decode("utf-16-le").rstrip("\x00")
        for m in uni_pat.finditer(raw)
    ]
    r["strings_ascii"]   = ascii_strs[:_MAX_ASCII_STR]
    r["strings_unicode"] = uni_strs[:_MAX_UNI_STR]
    r["strings_truncated"] = (
        len(ascii_strs) > _MAX_ASCII_STR or len(uni_strs) > _MAX_UNI_STR
    )


# ── Packer clues ─────────────────────────────────────────────────────

def _add_packer_clues(r: dict, pe: "pefile.PE") -> None:
    clues: list[str] = []

    # Known packer section names
    for s in r.get("sections", []):
        label = _PACKER_SECTIONS.get(s["name"])
        if label and label not in clues:
            clues.append(f"Section name '{s['name']}' → {label}")

    # High-entropy sections
    high = [s for s in r.get("sections", []) if s["entropy"] > _HIGH_ENTROPY]
    if high:
        names = ", ".join(s["name"] for s in high)
        clues.append(f"High-entropy section(s): {names}")

    # Very few imports — common after IAT obfuscation
    total_imports = sum(len(i["functions"]) for i in r.get("imports", []))
    if total_imports < 3 and r.get("num_sections", 0) > 0:
        clues.append(f"Only {total_imports} import(s) — possible IAT obfuscation")

    r["packer_clues"] = clues


# ── Anomalies ────────────────────────────────────────────────────────

def _add_anomalies(r: dict, pe: "pefile.PE", raw: bytes) -> None:
    anomalies: list[str] = []

    ts = r.get("compile_timestamp", 0)
    if ts == 0:
        anomalies.append("Compile timestamp is zero (stripped or invalid)")
    elif ts < 946_684_800:   # before 2000-01-01
        anomalies.append(f"Compile timestamp predates year 2000: {r.get('compile_timestamp_str')}")
    elif ts > time.time():
        anomalies.append(f"Compile timestamp is in the future: {r.get('compile_timestamp_str')}")

    if not r.get("imports"):
        anomalies.append("No import table present")

    ep = r.get("entry_point", 0)
    sections = r.get("sections", [])
    if sections:
        last = sections[-1]
        ep_va = ep
        last_va = last["virtual_address"]
        last_vs = last["virtual_size"]
        if last_va <= ep_va < last_va + last_vs:
            anomalies.append(
                f"Entry point is in the last section ('{last['name']}') — common in packers"
            )

    # Section with W+X (writable + executable)
    for s in sections:
        if "W" in s.get("characteristics", "") and "X" in s.get("characteristics", ""):
            anomalies.append(f"Section '{s['name']}' is both writable and executable (W+X)")

    if r.get("has_overlay") and r.get("overlay_size", 0) > 1024:
        anomalies.append(
            f"Executable has {r['overlay_size']:,} byte overlay "
            f"(entropy {r.get('overlay_entropy', 0):.2f})"
        )

    r["anomalies"] = anomalies


# ── Risk score ───────────────────────────────────────────────────────

def _score(r: dict) -> None:
    score = 0
    indicators: list[str] = []

    susp = r.get("suspicious_imports", [])
    if susp:
        pts = min(len(susp) * 3, 30)
        score += pts
        indicators.append(f"{len(susp)} suspicious API(s): {', '.join(susp[:6])}"
                          + (" …" if len(susp) > 6 else ""))

    # Classic injection triad is a stronger combined signal
    triad = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
    if triad.issubset(set(susp)):
        score += 15
        indicators.append("Classic injection triad present")

    high_ent = [s for s in r.get("sections", []) if s["entropy"] > _HIGH_ENTROPY]
    if high_ent:
        score += 15
        indicators.append(f"{len(high_ent)} section(s) with entropy > {_HIGH_ENTROPY}")
        if any(s["entropy"] > _VERY_HIGH_ENT for s in high_ent):
            score += 5
            indicators.append(f"Section entropy > {_VERY_HIGH_ENT} (likely encrypted)")

    if not r.get("imports"):
        score += 15
        indicators.append("No import table (IAT obfuscation or manual mapping)")

    if r.get("packer_clues"):
        score += 20
        indicators.extend(r["packer_clues"])

    if r.get("has_overlay") and r.get("overlay_size", 0) > 1024:
        score += 5
        indicators.append(f"Overlay present ({r['overlay_size']:,} bytes)")

    ts = r.get("compile_timestamp", 0)
    if ts == 0 or ts < 946_684_800 or ts > time.time():
        score += 10
        indicators.append("Suspicious compile timestamp")

    for s in r.get("sections", []):
        if "W" in s.get("characteristics", "") and "X" in s.get("characteristics", ""):
            score += 10
            indicators.append(f"W+X section: {s['name']}")
            break

    r["risk_score"]      = min(score, 100)
    r["risk_indicators"] = indicators


# ── Helpers ──────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _read_file(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None
