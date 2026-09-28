from __future__ import annotations

import hashlib
import io
import math
import mmap
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import zlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import BinaryIO, Iterable

from advanced_layers import analyze_file


# ---------------------------------------------------------------------------
# Resource limits: the public Render service is intentionally bounded.
# ---------------------------------------------------------------------------
SCAN_CHUNK_BYTES = 1024 * 1024
ENTROPY_SAMPLE_BYTES = 1024 * 1024
MAX_STRING_SCAN_BYTES = 20 * 1024 * 1024
MAX_WIDE_SCAN_BYTES = 8 * 1024 * 1024
MAX_RESOURCE_SCAN_BYTES = 4 * 1024 * 1024
MAX_PYI_ENTRY_BYTES = 2 * 1024 * 1024
MAX_PYI_TOTAL_DECOMPRESSED = 8 * 1024 * 1024
MAX_FINDINGS = 120

# ---------------------------------------------------------------------------
# String / script indicators. These are evidence, not signatures.
# ---------------------------------------------------------------------------
# needle, points, name, category
PATTERNS: list[tuple[bytes, int, str, str]] = [
    # PowerShell / scripting execution
    (b"downloadstring", 18, "PowerShell downloader", "network"),
    (b"invoke-expression", 18, "PowerShell dynamic execution", "execution"),
    (b"frombase64string", 8, "Base64 decode", "encoding"),
    (b"-executionpolicy bypass", 14, "Execution policy bypass", "evasion"),
    (b"-ep bypass", 12, "Execution policy bypass", "evasion"),
    (b"-windowstyle hidden", 10, "Hidden PowerShell", "evasion"),
    (b"-w hidden", 10, "Hidden PowerShell", "evasion"),
    (b"new-object net.webclient", 14, "WebClient downloader", "network"),
    (b"invoke-webrequest", 10, "PowerShell web request", "network"),
    (b"start-bitstransfer", 14, "BITS transfer", "network"),
    (b"certutil -urlcache", 18, "Certutil downloader", "execution"),
    (b"bitsadmin /transfer", 18, "BITSAdmin downloader", "execution"),
    (b"mshta ", 18, "MSHTA execution", "execution"),
    (b"regsvr32 ", 12, "Regsvr32 execution", "execution"),
    (b"rundll32 ", 10, "Rundll32 execution", "execution"),
    (b"wscript.shell", 10, "Windows Script Host shell", "execution"),
    (b"shell.application", 8, "Shell automation", "execution"),
    (b"cmd.exe /c", 8, "Command shell execution", "execution"),
    (b"-encodedcommand", 16, "PowerShell encoded command", "evasion"),
    (b"powershell -nop", 8, "PowerShell no-profile execution", "evasion"),
    (b"reflection.assembly]::load", 18, ".NET in-memory assembly load", "execution"),
    (b"system.management.automation.amsiutils", 24, "PowerShell AMSI internals reference", "evasion"),
    (b"[runtime.interopservices.marshal]::copy", 12, "PowerShell/.NET memory copy", "injection"),

    # Process injection / memory manipulation
    (b"writeprocessmemory", 16, "Process memory writing", "injection"),
    (b"createremotethread", 18, "Remote thread creation", "injection"),
    (b"ntcreatethreadex", 18, "Native remote thread creation", "injection"),
    (b"virtualallocex", 14, "Remote process allocation", "injection"),
    (b"queueuserapc", 14, "APC execution", "injection"),
    (b"setthreadcontext", 14, "Thread context manipulation", "injection"),
    (b"ntunmapviewofsection", 16, "Process hollowing primitive", "injection"),
    (b"rtlcreateuserthread", 16, "Native thread creation", "injection"),
    (b"openprocess", 6, "Process handle access", "injection"),

    # Persistence
    (b"currentversion\\run", 6, "Run-key persistence path", "persistence"),
    (b"currentversion\\runonce", 6, "RunOnce persistence path", "persistence"),
    (b"\\startup", 4, "Startup-folder reference", "persistence"),
    (b"schtasks /create", 18, "Scheduled-task persistence", "persistence"),
    (b"sc create", 14, "Service creation command", "persistence"),
    (b"createservicew", 6, "Service creation API", "persistence"),
    (b"createservicea", 6, "Service creation API", "persistence"),

    # Credential / browser theft indicators
    (b"cryptunprotectdata", 16, "DPAPI decryption API", "credential_access"),
    (b"credreadw", 16, "Windows credential read API", "credential_access"),
    (b"credenumeratew", 16, "Windows credential enumeration", "credential_access"),
    (b"vaultenumeratevaults", 18, "Windows Vault enumeration", "credential_access"),
    (b"\\google\\chrome\\user data", 14, "Chrome profile path", "credential_access"),
    (b"\\microsoft\\edge\\user data", 14, "Edge profile path", "credential_access"),
    (b"\\mozilla\\firefox\\profiles", 14, "Firefox profile path", "credential_access"),
    (b"logins.json", 10, "Firefox login database", "credential_access"),
    (b"key4.db", 10, "Firefox key database", "credential_access"),
    (b"cookies.sqlite", 8, "Firefox cookie database", "credential_access"),
    (b"wallet.dat", 12, "Cryptocurrency wallet database", "credential_access"),
    (b"metamask", 8, "Browser wallet marker", "credential_access"),
    (b"login data", 8, "Browser login database", "credential_access"),
    (b"local state", 6, "Chromium Local State", "credential_access"),
    (b"\\cookies", 5, "Browser cookie storage", "credential_access"),
    (b"discord\\local storage\\leveldb", 14, "Discord token storage path", "credential_access"),
    (b"telegram desktop\\tdata", 14, "Telegram session storage path", "credential_access"),
    (b"electrum\\wallets", 14, "Cryptocurrency wallet path", "credential_access"),

    # Defense evasion / anti-analysis
    (b"isdebuggerpresent", 4, "Debugger detection", "evasion"),
    (b"checkremotedebuggerpresent", 4, "Remote debugger detection", "evasion"),
    (b"ntqueryinformationprocess", 5, "Native process inspection", "evasion"),
    (b"amsiscanbuffer", 8, "AMSI interface reference", "evasion"),
    (b"amsiinitfailed", 18, "AMSI bypass indicator", "evasion"),
    (b"set-mppreference -disablerealtimemonitoring", 30, "Defender disabling command", "evasion"),
    (b"add-mppreference -exclusion", 22, "Defender exclusion command", "evasion"),
    (b"sc stop windefend", 25, "Defender service stop command", "evasion"),
    (b"wevtutil cl ", 18, "Event-log clearing command", "evasion"),
    (b"vssadmin delete shadows", 28, "Shadow-copy deletion", "destructive"),
    (b"wmic shadowcopy delete", 28, "Shadow-copy deletion", "destructive"),
    (b"bcdedit /set", 12, "Boot configuration modification", "evasion"),
    (b"\\sandboxie", 8, "Sandbox detection string", "evasion"),
    (b"vboxservice", 8, "VirtualBox detection string", "evasion"),
    (b"vmtoolsd", 8, "VMware detection string", "evasion"),
    (b"procmon", 6, "Process Monitor detection string", "evasion"),
    (b"wireshark", 6, "Wireshark detection string", "evasion"),

    # Network / C2 / exfiltration
    (b"urldownloadtofile", 16, "URLDownloadToFile API", "network"),
    (b"internetopenurl", 10, "WinINet URL access", "network"),
    (b"httpsendrequest", 6, "WinINet HTTP request", "network"),
    (b"winhttpopenrequest", 8, "WinHTTP request", "network"),
    (b"discord.com/api/webhooks", 18, "Discord webhook endpoint", "exfiltration"),
    (b"api.telegram.org/bot", 18, "Telegram Bot API endpoint", "exfiltration"),
    (b"stratum+tcp://", 22, "Cryptomining Stratum endpoint", "mining"),
    (b"xmrig", 20, "XMRig miner marker", "mining"),
    (b"cryptonight", 16, "CryptoNight miner marker", "mining"),

    # Discovery commands (low weight: common in admin tools too)
    (b"ipconfig /all", 4, "Network discovery command", "discovery"),
    (b"systeminfo", 3, "System discovery command", "discovery"),
    (b"whoami /all", 4, "Identity discovery command", "discovery"),
    (b"net user", 4, "Account discovery command", "discovery"),
    (b"tasklist", 3, "Process discovery command", "discovery"),
    (b"netstat -ano", 4, "Network connection discovery", "discovery"),
]

_PATTERN_OVERLAP = max(len(p[0]) for p in PATTERNS) - 1
PATTERN_MAP = {needle: (pts, name, category) for needle, pts, name, category in PATTERNS}
PATTERN_RE = re.compile(b"|".join(re.escape(x) for x in sorted(PATTERN_MAP, key=len, reverse=True)))
WIDE_MAP = {
    b"".join(bytes((c, 0)) for c in needle): (needle, pts, name, category)
    for needle, pts, name, category in PATTERNS if len(needle) >= 5
}
WIDE_RE = re.compile(b"|".join(re.escape(x) for x in sorted(WIDE_MAP, key=len, reverse=True)))

ASCII_URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{6,240}", re.I)
IPV4_RE = re.compile(rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")

# Imports are scored by category, not one-by-one, to reduce false positives.
IMPORT_CATEGORIES: dict[str, tuple[int, set[str]]] = {
    "injection": (8, {
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc",
        "setthreadcontext", "ntunmapviewofsection", "mapviewoffileex",
        "openprocess", "suspendthread", "resumethread",
    }),
    "network": (8, {
        "internetopena", "internetopenw", "internetopenurla", "internetopenurlw",
        "httpopenrequesta", "httpopenrequestw", "httpsendrequesta", "httpsendrequestw",
        "winhttpopen", "winhttpconnect", "winhttpopenrequest", "winhttpsendrequest",
        "urldownloadtofilea", "urldownloadtofilew", "wsastartup", "connect", "recv", "send",
    }),
    "credential_access": (18, {
        "cryptunprotectdata", "credreadw", "credreada", "credenumeratew", "credenumeratea",
        "vaultenumeratevaults", "vaultopenvault", "vaultenumerateitems", "lsaopenpolicy",
        "minidumpwritedump",
    }),
    "persistence": (8, {
        "regsetvalueexa", "regsetvalueexw", "createservicea", "createservicew",
        "startservicea", "startservicew", "changeserviceconfiga", "changeserviceconfigw",
    }),
    "evasion": (6, {
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "virtualprotect", "virtualprotectex", "setunhandledexceptionfilter",
        "outputdebugstringa", "outputdebugstringw",
    }),
    "execution": (4, {
        "createprocessa", "createprocessw", "shellexecutea", "shellexecutew",
        "shellexecuteexa", "shellexecuteexw", "winexec",
    }),
    "privilege": (8, {
        "openprocesstoken", "adjusttokenprivileges", "lookupprivilegevaluea",
        "lookupprivilegevaluew", "impersonateloggedonuser", "duplicatetokenex",
    }),
    "crypto": (2, {
        "cryptencrypt", "cryptdecrypt", "bcryptencrypt", "bcryptdecrypt",
        "cryptacquirecontexta", "cryptacquirecontextw", "bcryptgeneratekeypair",
        "bcryptgeneratesymmetrickey", "bcryptderivekey", "cryptgenkey",
    }),
    "filesystem": (2, {
        "findfirstfilea", "findfirstfilew", "findnextfilea", "findnextfilew",
        "createfilea", "createfilew", "readfile", "writefile", "deletefilea",
        "deletefilew", "movefilea", "movefilew", "movefileexa", "movefileexw",
        "setfileinformationbyhandle",
    }),
    "resolver": (4, {
        "getprocaddress", "loadlibrarya", "loadlibraryw", "ldrloaddll",
        "ldrgetprocedureaddress", "getmodulehandlea", "getmodulehandlew",
    }),
}

PACKER_SECTION_NAMES = {
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".mpress1", ".mpress2",
    ".vmp0", ".vmp1", ".themida", ".packed", "petite", ".boom",
}

PYINSTALLER_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
PYINSTALLER_MARKERS = (
    b"pyinstaller", b"pyi_rth_", b"_pyi_main_co", b"pyiboot01_bootstrap",
    b"pyimod02_importers", b"pyimod03_ctypes", b"pyz-00.pyz", b"python3",
)


def entropy(data: bytes | bytearray) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class _Evidence:
    def __init__(self) -> None:
        self.score = 0
        self.findings: list[dict] = []
        self.categories: set[str] = set()
        self.pattern_hits: set[bytes] = set()
        self.import_hits: set[str] = set()
        self.tags: set[str] = set()
        # Analysis-control flags are not threat tags and never affect verdict
        # directly. They let deeper parsers suppress shallow lexical clusters
        # when the same words occur only as inert script data/comments.
        self.flags: set[str] = set()
        self._seen: set[tuple[str, str]] = set()

    def add(self, points: int, name: str, detail: str, category: str | None = None) -> None:
        if len(self.findings) >= MAX_FINDINGS:
            return
        key = (name, detail)
        if key in self._seen:
            return
        self._seen.add(key)
        self.score += int(points)
        if category:
            self.categories.add(category)
        self.findings.append({
            "name": name,
            "score": int(points),
            "detail": detail,
            **({"category": category} if category else {}),
        })


def _decode_name(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _scan_indicator_buffer(data: bytes, ev: _Evidence, *, context: str = "file", include_ascii: bool = True) -> None:
    low = data.lower()
    if include_ascii:
        for match in PATTERN_RE.finditer(low):
            needle = match.group(0)
            info = PATTERN_MAP.get(needle)
            if not info:
                continue
            pts, name, category = info
            ev.pattern_hits.add(needle)
            ev.add(pts, name, f"{needle.decode('ascii', 'ignore')} ({context})", category)

    # UTF-16LE equivalents catch many Windows/.NET strings.
    for match in WIDE_RE.finditer(low):
        wide = match.group(0)
        info = WIDE_MAP.get(wide)
        if not info:
            continue
        needle, pts, name, category = info
        ev.pattern_hits.add(needle)
        ev.add(max(2, pts - 2), name, f"UTF-16 {needle.decode('ascii', 'ignore')} ({context})", category)


def _stream_scan(stream: BinaryIO, filename: str, ev: _Evidence, *, precomputed_sha256: str | None = None) -> tuple[str, int, bytes, float, dict]:
    hasher = None if precomputed_sha256 else hashlib.sha256()
    total = 0
    first_two = b""
    entropy_sample = bytearray()
    tail = b""
    remaining = dict(PATTERN_MAP)
    saw_powershell = False
    saw_hidden = False
    saw_download_or_http = False
    saw_url = False
    saw_ip = False
    pyi_marker_hits: set[bytes] = set()

    while True:
        chunk = stream.read(SCAN_CHUNK_BYTES)
        if not chunk:
            break

        if not first_two:
            first_two = chunk[:2]
        total += len(chunk)
        if hasher is not None:
            hasher.update(chunk)

        if len(entropy_sample) < ENTROPY_SAMPLE_BYTES:
            need = ENTROPY_SAMPLE_BYTES - len(entropy_sample)
            entropy_sample.extend(chunk[:need])

        low = (tail + chunk).lower()

        for match in PATTERN_RE.finditer(low):
            needle = match.group(0)
            info = remaining.pop(needle, None)
            if info is None:
                continue
            pts, name, category = info
            ev.pattern_hits.add(needle)
            ev.add(pts, name, needle.decode("ascii", "ignore"), category)

        if not saw_powershell and b"powershell" in low:
            saw_powershell = True
        if not saw_hidden and b"hidden" in low:
            saw_hidden = True
        if not saw_download_or_http and (b"download" in low or b"http" in low):
            saw_download_or_http = True

        if not saw_url and ASCII_URL_RE.search(low):
            saw_url = True
        if not saw_ip and IPV4_RE.search(low):
            saw_ip = True

        for marker in PYINSTALLER_MARKERS:
            if marker in low:
                pyi_marker_hits.add(marker)

        # Also scan UTF-16LE representation for the most important indicators.
        if total <= MAX_WIDE_SCAN_BYTES:
            _scan_indicator_buffer(low, ev, context="raw", include_ascii=False)

        tail = low[-_PATTERN_OVERLAP:] if _PATTERN_OVERLAP else b""

    sha256 = precomputed_sha256 or (hasher.hexdigest() if hasher is not None else "")
    sample_entropy = entropy(entropy_sample)

    if saw_powershell and saw_hidden and saw_download_or_http:
        ev.add(30, "Hidden downloader combination", "PowerShell + hidden + network/download behavior", "execution")
    if saw_url:
        ev.add(4, "Embedded URL", "One or more HTTP/HTTPS URLs found", "network")
    if saw_ip:
        ev.add(2, "Embedded IPv4 address", "One or more IPv4-like strings found", "network")

    meta = {
        "pyinstaller_markers": [m.decode("ascii", "ignore") for m in sorted(pyi_marker_hits)],
    }
    return sha256, total, first_two, sample_entropy, meta



def _u16(mm: mmap.mmap, off: int) -> int:
    if off < 0 or off + 2 > len(mm):
        raise ValueError("u16 out of range")
    return struct.unpack_from("<H", mm, off)[0]


def _u32(mm: mmap.mmap, off: int) -> int:
    if off < 0 or off + 4 > len(mm):
        raise ValueError("u32 out of range")
    return struct.unpack_from("<I", mm, off)[0]


def _u64(mm: mmap.mmap, off: int) -> int:
    if off < 0 or off + 8 > len(mm):
        raise ValueError("u64 out of range")
    return struct.unpack_from("<Q", mm, off)[0]


def _read_c_string(mm: mmap.mmap, off: int, max_len: int = 512) -> str:
    if off < 0 or off >= len(mm):
        return ""
    end = min(len(mm), off + max_len)
    pos = mm.find(b"\x00", off, end)
    if pos < 0:
        pos = end
    return bytes(mm[off:pos]).decode("utf-8", "replace")


def _rva_to_offset(rva: int, sections: list[dict], file_size: int) -> int | None:
    if rva <= 0:
        return None
    for sec in sections:
        va = sec["virtual_address"]
        span = max(sec["virtual_size"], sec["raw_size"])
        if va <= rva < va + span:
            off = sec["raw_ptr"] + (rva - va)
            if 0 <= off < file_size:
                return off
    # Header RVAs can map directly.
    if 0 <= rva < file_size:
        return rva
    return None


def _parse_import_table(
    mm: mmap.mmap,
    sections: list[dict],
    rva: int,
    size: int,
    *,
    is_64: bool,
    image_base: int,
    delay: bool = False,
) -> tuple[set[str], set[str]]:
    """Return (imported function names, DLL names), safely bounded."""
    names: set[str] = set()
    dlls: set[str] = set()
    file_size = len(mm)
    base_off = _rva_to_offset(rva, sections, file_size)
    if base_off is None:
        return names, dlls

    ptr_size = 8 if is_64 else 4
    ordinal_mask = 0x8000000000000000 if is_64 else 0x80000000
    max_descriptors = 256

    for i in range(max_descriptors):
        try:
            if delay:
                off = base_off + i * 32
                if off + 32 > file_size:
                    break
                attrs, name_field, _, iat, int_field, _, _, _ = struct.unpack_from("<IIIIIIII", mm, off)
                if not any((attrs, name_field, iat, int_field)):
                    break
                # Delay descriptors may contain VAs when Attrs bit 0 is clear.
                def norm(v: int) -> int:
                    if not v:
                        return 0
                    return v if (attrs & 1) else max(0, v - image_base)
                name_rva = norm(name_field)
                thunk_rva = norm(int_field) or norm(iat)
            else:
                off = base_off + i * 20
                if off + 20 > file_size:
                    break
                original_first_thunk, time_date, forwarder, name_rva, first_thunk = struct.unpack_from("<IIIII", mm, off)
                if not any((original_first_thunk, time_date, forwarder, name_rva, first_thunk)):
                    break
                thunk_rva = original_first_thunk or first_thunk

            name_off = _rva_to_offset(name_rva, sections, file_size)
            if name_off is not None:
                dll = _read_c_string(mm, name_off, 260).lower()
                if dll:
                    dlls.add(dll)

            thunk_off = _rva_to_offset(thunk_rva, sections, file_size)
            if thunk_off is None:
                continue

            for j in range(2048):
                ent_off = thunk_off + j * ptr_size
                if ent_off + ptr_size > file_size:
                    break
                value = _u64(mm, ent_off) if is_64 else _u32(mm, ent_off)
                if value == 0:
                    break
                if value & ordinal_mask:
                    continue
                hint_name_off = _rva_to_offset(int(value), sections, file_size)
                if hint_name_off is None or hint_name_off + 2 >= file_size:
                    continue
                fn = _read_c_string(mm, hint_name_off + 2, 256).lower()
                if fn:
                    names.add(fn)
        except Exception:
            break

    return names, dlls


def _score_imports(all_imports: set[str], ev: _Evidence) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for category, (base_points, known_names) in IMPORT_CATEGORIES.items():
        matched = sorted(x for x in all_imports if x in known_names)
        if not matched:
            continue
        ev.import_hits.update(matched)

        # Generic APIs are common in installers and legitimate tools. Score
        # combinations more than isolated imports.
        points = base_points
        if category == "injection":
            core = set(matched) & {
                "virtualallocex", "writeprocessmemory", "createremotethread",
                "ntcreatethreadex", "rtlcreateuserthread", "queueuserapc",
                "setthreadcontext", "ntunmapviewofsection",
            }
            points = 4 if not core else 10 + min(20, max(0, len(core) - 1) * 6)
        elif category == "credential_access":
            points = 12 + min(18, max(0, len(matched) - 1) * 6)
        elif category in {"network", "persistence", "evasion"}:
            points = base_points + min(8, max(0, len(matched) - 1) * 2)
        elif category == "execution":
            points = 4 + min(4, max(0, len(matched) - 1) * 2)
        elif category == "privilege":
            points = 6 + min(8, max(0, len(matched) - 1) * 2)
        elif category == "crypto":
            points = 2 + min(6, max(0, len(matched) - 1) * 2)
        elif category == "filesystem":
            points = 2 + min(4, max(0, len(matched) - 2))
        elif category == "resolver":
            points = 4 + min(6, max(0, len(matched) - 1) * 2)

        ev.add(points, f"Suspicious {category.replace('_', ' ')} imports", ", ".join(matched[:8]), category)
        hits[category] = matched
    return hits


def _derive_tags(ev: _Evidence) -> set[str]:
    p = ev.pattern_hits
    i = ev.import_hits
    suppress_script_patterns = "suppress_raw_script_combo_tags" in ev.flags

    injection_names = {
        b"virtualallocex", b"writeprocessmemory", b"createremotethread",
        b"ntcreatethreadex", b"rtlcreateuserthread", b"queueuserapc",
        b"setthreadcontext", b"ntunmapviewofsection",
    }
    injection_import_names = {x.decode() for x in injection_names}
    inj_count = len(p & injection_names) + len(i & injection_import_names)
    if inj_count >= 3 and not suppress_script_patterns:
        ev.tags.add("injection_chain")

    credential_names = {
        b"cryptunprotectdata", b"credreadw", b"credenumeratew",
        b"vaultenumeratevaults", b"\\google\\chrome\\user data",
        b"\\microsoft\\edge\\user data", b"\\mozilla\\firefox\\profiles",
        b"discord\\local storage\\leveldb", b"telegram desktop\\tdata",
        b"electrum\\wallets",
    }
    cred_count = len(p & credential_names) + len(i & {
        "cryptunprotectdata", "credreadw", "credreada", "credenumeratew",
        "credenumeratea", "vaultenumeratevaults", "vaultopenvault", "vaultenumerateitems",
        "minidumpwritedump",
    })
    if cred_count >= 2 and not suppress_script_patterns:
        ev.tags.add("credential_theft_cluster")

    if (not suppress_script_patterns) and p & {
        b"set-mppreference -disablerealtimemonitoring",
        b"add-mppreference -exclusion", b"sc stop windefend",
    }:
        ev.tags.add("defense_disable")

    if (not suppress_script_patterns) and p & {b"vssadmin delete shadows", b"wmic shadowcopy delete"}:
        ev.tags.add("destructive_recovery_inhibition")

    if (not suppress_script_patterns) and p & {b"discord.com/api/webhooks", b"api.telegram.org/bot"}:
        ev.tags.add("exfiltration_channel")

    if (not suppress_script_patterns) and b"stratum+tcp://" in p and (b"xmrig" in p or b"cryptonight" in p):
        ev.tags.add("miner_cluster")

    persist = p & {
        b"currentversion\\run", b"currentversion\\runonce", b"\\startup",
        b"schtasks /create", b"sc create", b"createservicew", b"createservicea",
    }
    active_persistence = persist & {b"schtasks /create", b"sc create", b"createservicew", b"createservicea"}
    if (not suppress_script_patterns) and (len(persist) >= 3 or (active_persistence and len(persist) >= 2)):
        ev.tags.add("persistence_cluster")

    downloader_bits = 0
    if p & {b"downloadstring", b"new-object net.webclient", b"invoke-webrequest", b"certutil -urlcache", b"bitsadmin /transfer"}:
        downloader_bits += 1
    if p & {b"invoke-expression", b"cmd.exe /c", b"mshta ", b"rundll32 ", b"regsvr32 "}:
        downloader_bits += 1
    if p & {b"-windowstyle hidden", b"-w hidden", b"-executionpolicy bypass", b"-ep bypass"}:
        downloader_bits += 1
    if downloader_bits >= 3 and not suppress_script_patterns:
        ev.tags.add("download_execute_evasion_chain")

    return ev.tags

def _analyze_pe(path: str, ev: _Evidence) -> dict:
    """Bounded pure-Python PE parser; no third-party PE package required."""
    file_size = os.path.getsize(path)
    if file_size < 0x100:
        ev.add(5, "Malformed or unusual PE", "File too small for normal PE headers", "structure")
        return {"pe_parser": "builtin", "status": "malformed"}

    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        try:
            if mm[:2] != b"MZ":
                return {"pe_parser": "builtin", "status": "not-pe"}
            pe_off = _u32(mm, 0x3C)
            if pe_off < 0x40 or pe_off + 24 > file_size or mm[pe_off:pe_off + 4] != b"PE\x00\x00":
                ev.add(8, "Malformed PE header", "MZ present but PE signature/header is invalid", "structure")
                return {"pe_parser": "builtin", "status": "malformed"}

            coff = pe_off + 4
            machine, num_sections, timestamp, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", mm, coff)
            opt = coff + 20
            if opt + opt_size > file_size or opt_size < 96:
                ev.add(8, "Malformed optional header", f"SizeOfOptionalHeader={opt_size}", "structure")
                return {"pe_parser": "builtin", "status": "malformed"}

            magic = _u16(mm, opt)
            if magic == 0x20B:
                is_64 = True
                image_base = _u64(mm, opt + 24)
                num_rva_off = opt + 108
                data_dir_off = opt + 112
            elif magic == 0x10B:
                is_64 = False
                image_base = _u32(mm, opt + 28)
                num_rva_off = opt + 92
                data_dir_off = opt + 96
            else:
                ev.add(8, "Unknown PE optional-header magic", hex(magic), "structure")
                return {"pe_parser": "builtin", "status": "malformed"}

            ep_rva = _u32(mm, opt + 16)
            subsystem = _u16(mm, opt + 68)
            dll_characteristics = _u16(mm, opt + 70)
            num_dirs = min(_u32(mm, num_rva_off), 16)

            def directory(index: int) -> tuple[int, int]:
                if index >= num_dirs:
                    return (0, 0)
                off = data_dir_off + index * 8
                if off + 8 > opt + opt_size or off + 8 > file_size:
                    return (0, 0)
                return struct.unpack_from("<II", mm, off)

            sec_table = opt + opt_size
            sections: list[dict] = []
            section_details: list[dict] = []
            high_entropy_exec = 0
            rwx_sections = 0
            packed_names: list[str] = []
            ep_section = None
            overlay_end = min(file_size, sec_table + num_sections * 40)

            for i in range(min(num_sections, 96)):
                off = sec_table + i * 40
                if off + 40 > file_size:
                    break
                name = bytes(mm[off:off + 8]).split(b"\x00", 1)[0].decode("ascii", "replace") or "<unnamed>"
                virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from("<IIII", mm, off + 8)
                chars = _u32(mm, off + 36)
                executable = bool(chars & 0x20000000)
                readable = bool(chars & 0x40000000)
                writable = bool(chars & 0x80000000)

                sec = {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_ptr": raw_ptr,
                    "characteristics": chars,
                }
                sections.append(sec)

                ent = 0.0
                if raw_size and raw_ptr < file_size:
                    sample_len = min(raw_size, 2 * 1024 * 1024, file_size - raw_ptr)
                    if sample_len > 0:
                        ent = entropy(mm[raw_ptr:raw_ptr + sample_len])
                    overlay_end = max(overlay_end, min(file_size, raw_ptr + raw_size))

                section_details.append({
                    "name": name,
                    "entropy": round(ent, 3),
                    "executable": executable,
                    "readable": readable,
                    "writable": writable,
                    "raw_size": raw_size,
                    "virtual_size": virtual_size,
                })

                lname = name.lower()
                if lname in PACKER_SECTION_NAMES or any(x in lname for x in ("upx", "vmp", "themida", "mpress", "aspack")):
                    packed_names.append(name)
                if executable and ent > 7.2 and raw_size >= 4096:
                    high_entropy_exec += 1
                if executable and writable:
                    rwx_sections += 1
                if virtual_address <= ep_rva < virtual_address + max(virtual_size, raw_size):
                    ep_section = (name, executable, writable, ent)

                # Resource sections often contain embedded configs/payloads.
                if lname in {".rsrc", "rsrc"} and raw_size and raw_ptr < file_size:
                    rlen = min(raw_size, MAX_RESOURCE_SCAN_BYTES, file_size - raw_ptr)
                    if rlen > 0:
                        blob = bytes(mm[raw_ptr:raw_ptr + rlen])
                        _scan_indicator_buffer(blob, ev, context="PE resource")
                        rent = entropy(blob[:min(len(blob), 1024 * 1024)])
                        if len(blob) >= 65536 and rent > 7.4:
                            ev.add(8, "High-entropy PE resources", f"resource entropy={rent:.3f}", "packer")

            machine_name = {
                0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64",
            }.get(machine, hex(machine))
            meta = {
                "pe_parser": "builtin",
                "status": "ok",
                "machine": machine_name,
                "sections": num_sections,
                "entry_point_rva": hex(ep_rva),
                "image_base": hex(image_base),
                "subsystem": subsystem,
                "dll_characteristics": hex(dll_characteristics),
                "section_details": section_details[:24],
            }

            if num_sections == 0 or num_sections > 12:
                ev.add(6, "Unusual PE section count", str(num_sections), "structure")
            now = int(time.time())
            if timestamp > now + 86400:
                ev.add(6, "Future PE compile timestamp", str(timestamp), "evasion")
            elif timestamp and timestamp < 946684800:
                ev.add(3, "Very old PE compile timestamp", str(timestamp), "structure")

            if packed_names:
                ev.add(25, "Known packer section marker", ", ".join(packed_names[:6]), "packer")
            if high_entropy_exec:
                ev.add(18 + min(12, 4 * (high_entropy_exec - 1)), "High-entropy executable section", f"count={high_entropy_exec}", "packer")
            if rwx_sections:
                ev.add(28 + min(12, 4 * (rwx_sections - 1)), "Writable + executable PE section", f"count={rwx_sections}", "injection")
            if ep_section and ep_section[2]:
                ev.add(18, "Entry point in writable section", f"section={ep_section[0]}", "injection")
            if rwx_sections and high_entropy_exec:
                ev.tags.add("rwx_packed_code")

            import_rva, import_size = directory(1)
            imports, dlls = _parse_import_table(mm, sections, import_rva, import_size, is_64=is_64, image_base=image_base)
            delay_rva, delay_size = directory(13)
            d_imports, d_dlls = _parse_import_table(mm, sections, delay_rva, delay_size, is_64=is_64, image_base=image_base, delay=True)
            imports |= d_imports
            dlls |= d_dlls
            import_hits = _score_imports(imports, ev)
            meta["import_count"] = len(imports)
            meta["dll_count"] = len(dlls)
            meta["import_dlls"] = sorted(dlls)[:40]
            meta["suspicious_imports"] = import_hits

            if (high_entropy_exec or packed_names) and len(imports) <= 5:
                ev.add(16, "Packed/obfuscated import profile", f"imports={len(imports)}", "packer")

            security_off, security_size = directory(4)  # file offset, not RVA
            signed = bool(security_off and security_size and security_off < file_size)
            meta["authenticode_present"] = signed
            if not signed:
                ev.add(2, "No embedded Authenticode signature", "PE has no certificate table", "structure")

            tls_rva, tls_size = directory(9)
            if tls_rva and tls_size:
                ev.add(6, "TLS directory present", "May contain pre-entry callbacks", "evasion")

            clr_rva, clr_size = directory(14)
            if clr_rva and clr_size:
                meta["dotnet"] = True
                ev.add(0, ".NET assembly", "CLR metadata directory present", "dotnet")
            else:
                meta["dotnet"] = False

            overlay_size = max(0, file_size - overlay_end)
            meta["overlay_size"] = overlay_size
            if overlay_size >= 512 * 1024 and overlay_size >= max(1, file_size // 5):
                ev.add(12, "Large PE overlay", f"{overlay_size} bytes appended", "packer")
            if overlay_size > 0:
                olen = min(overlay_size, 4 * 1024 * 1024)
                overlay = bytes(mm[overlay_end:overlay_end + olen])
                _scan_indicator_buffer(overlay, ev, context="PE overlay")
                # An embedded PE is common in installers, but still valuable
                # dropper/loader evidence when corroborated by other signals.
                if overlay.find(b"MZ") >= 0:
                    ev.add(10, "Embedded PE-like payload in overlay", "MZ marker found in appended data", "dropper")

            return meta
        except Exception as exc:
            ev.add(5, "Malformed or unusual PE", type(exc).__name__, "structure")
            return {"pe_parser": "builtin", "status": "error", "error": type(exc).__name__}

def _find_pyi_cookie(path: str) -> tuple[int, bytes] | None:
    size = os.path.getsize(path)
    tail_size = min(size, 1024 * 1024)
    with open(path, "rb") as f:
        f.seek(size - tail_size)
        tail = f.read(tail_size)
    idx = tail.rfind(PYINSTALLER_MAGIC)
    if idx < 0:
        return None
    return size - tail_size + idx, tail[idx:]


def _analyze_pyinstaller(path: str, ev: _Evidence, raw_markers: Iterable[str]) -> dict:
    marker_list = list(raw_markers)
    cookie = _find_pyi_cookie(path)
    if not cookie and not marker_list:
        return {"detected": False}

    ev.add(6, "PyInstaller bundle", "PyInstaller bootloader/archive markers detected", "pyinstaller")
    meta = {"detected": True, "entries_scanned": 0, "embedded_bytes_scanned": 0}

    if not cookie:
        return meta

    cookie_pos, cookie_tail = cookie
    file_size = os.path.getsize(path)

    # Prefer the modern 88-byte cookie; fall back to the 24-byte old cookie.
    parsed = None
    for cookie_size, fmt in ((88, "!8sIIII64s"), (24, "!8siiii")):
        if cookie_pos + cookie_size > file_size:
            continue
        try:
            with open(path, "rb") as f:
                f.seek(cookie_pos)
                buf = f.read(cookie_size)
            vals = struct.unpack(fmt, buf)
            magic = vals[0]
            if magic != PYINSTALLER_MAGIC:
                continue
            pkg_len = int(vals[1])
            toc_pos = int(vals[2])
            toc_len = int(vals[3])
            pyver = int(vals[4])
            if pkg_len <= 0 or toc_len <= 0 or toc_len > pkg_len:
                continue
            package_start = cookie_pos + cookie_size - pkg_len
            if package_start < 0 or package_start + toc_pos + toc_len > file_size:
                continue
            parsed = (cookie_size, package_start, toc_pos, toc_len, pyver)
            break
        except Exception:
            continue

    if not parsed:
        ev.add(4, "PyInstaller archive cookie", "Archive detected but TOC could not be parsed safely", "pyinstaller")
        return meta

    _, package_start, toc_pos, toc_len, pyver = parsed
    meta["python_version_code"] = pyver

    total_decompressed = 0
    interesting_names: list[str] = []

    try:
        with open(path, "rb") as f:
            f.seek(package_start + toc_pos)
            toc = f.read(min(toc_len, 4 * 1024 * 1024))

            p = 0
            while p + 18 <= len(toc) and meta["entries_scanned"] < 250:
                try:
                    entry_size = struct.unpack_from("!I", toc, p)[0]
                except struct.error:
                    break
                if entry_size < 18 or p + entry_size > len(toc):
                    break
                try:
                    pos, comp_size, uncomp_size = struct.unpack_from("!III", toc, p + 4)
                    comp_flag = toc[p + 16]
                    type_code = chr(toc[p + 17])
                    name_bytes = toc[p + 18:p + entry_size].split(b"\x00", 1)[0]
                    name = name_bytes.decode("utf-8", "replace")
                except Exception:
                    p += entry_size
                    continue

                meta["entries_scanned"] += 1
                lname = name.lower()
                if any(x in lname for x in (
                    "requests", "urllib", "socket", "subprocess", "ctypes", "winreg",
                    "browser", "cookie", "password", "token", "wallet", "pynput",
                    "keylog", "discord", "telegram", "crypto", "miner", "inject",
                )):
                    interesting_names.append(name)

                # Scan only bounded entries. Never execute/unmarshal code.
                if (
                    comp_size > 0
                    and comp_size <= MAX_PYI_ENTRY_BYTES
                    and uncomp_size <= MAX_PYI_ENTRY_BYTES
                    and total_decompressed < MAX_PYI_TOTAL_DECOMPRESSED
                    and 0 <= package_start + pos < file_size
                ):
                    try:
                        fpos = f.tell()
                        f.seek(package_start + pos)
                        blob = f.read(comp_size)
                        f.seek(fpos)
                        if comp_flag:
                            blob = zlib.decompress(blob)
                        if len(blob) > MAX_PYI_ENTRY_BYTES:
                            blob = blob[:MAX_PYI_ENTRY_BYTES]
                        total_decompressed += len(blob)
                        _scan_indicator_buffer(blob, ev, context=f"PyInstaller:{name or type_code}")
                    except Exception:
                        pass

                p += entry_size
    except Exception:
        pass

    meta["embedded_bytes_scanned"] = total_decompressed
    meta["interesting_entry_names"] = interesting_names[:30]
    if interesting_names:
        ev.add(8, "Interesting PyInstaller module names", ", ".join(interesting_names[:8]), "pyinstaller")

    return meta


def _static_verdict(ev: _Evidence) -> tuple[str, str, list[str]]:
    tags = _derive_tags(ev)
    cats = set(ev.categories)

    # High-confidence malicious is based on specific behavior clusters, not
    # generic PE traits or a numeric score alone. This is deliberately harder
    # to trigger than "suspicious" to reduce installer/packer false positives.
    strong = set(tags)
    reasons: list[str] = []

    # V4 family-agnostic high-confidence clusters.  These are behavioral
    # combinations, not malware-family names and not score-only decisions.
    if "ransomware_mass_encryption" in strong and ev.score >= 55:
        reasons.append("bulk file enumeration + encryption + repeated overwrite behavior")
        return "malicious", "high", reasons

    if "ransomware_destructive" in strong and ev.score >= 50:
        reasons.append("mass encryption combined with destructive/recovery-impact behavior")
        return "malicious", "high", reasons

    if "powershell_encoded_payload_chain" in strong and ev.score >= 50 and (cats & {"execution", "network", "injection", "evasion"}):
        reasons.append("encoded/decoded PowerShell payload with executable or network behavior")
        return "malicious", "high", reasons

    if "powershell_download_execute_chain" in strong and ev.score >= 50 and (cats & {"network", "execution"}):
        reasons.append("PowerShell download + dynamic execution chain")
        return "malicious", "high", reasons

    if "python_credential_exfil_cluster" in strong and ev.score >= 50:
        reasons.append("Python credential-access indicators combined with network capability")
        return "malicious", "high", reasons

    if "python_input_capture_exfil_cluster" in strong and ev.score >= 50:
        reasons.append("Python input-capture indicators combined with network capability")
        return "malicious", "high", reasons

    if "pyinstaller_embedded_behavior" in strong and ev.score >= 55 and (cats & {"credential_access", "network", "execution", "pyinstaller"}):
        reasons.append("PyInstaller bundle contains corroborating embedded high-risk behavior")
        return "malicious", "high", reasons

    if "embedded_payload_loader" in strong and ev.score >= 55 and (cats & {"dropper", "loader", "packer", "execution", "injection"}):
        reasons.append("loader/packer contains a recoverable embedded executable payload")
        return "malicious", "high", reasons

    if "dynamic_resolver_stager" in strong and "tiny_sparse_loader" in strong and ev.score >= 55:
        reasons.append("tiny unsigned sparse-import executable with PEB/API-resolution stager behavior")
        return "malicious", "high", reasons

    if "dynamic_resolver_stager" in strong and ev.score >= 55 and (cats & {"injection", "network", "evasion", "dropper"}):
        reasons.append("sparse-import stager with dynamic API-resolution and corroborating behavior")
        return "malicious", "high", reasons

    if len(strong) >= 2 and ev.score >= 70:
        reasons.append("multiple independent high-risk behavior clusters")
        return "malicious", "high", reasons

    if "injection_chain" in strong and ev.score >= 65 and (cats & {"network", "execution", "evasion", "persistence"}):
        reasons.append("process-injection chain with corroborating behavior")
        return "malicious", "high", reasons

    if "credential_theft_cluster" in strong and ev.score >= 65 and (cats & {"network", "exfiltration", "execution"}):
        reasons.append("credential-access cluster with delivery/exfiltration evidence")
        return "malicious", "high", reasons

    if "defense_disable" in strong and ev.score >= 60 and (cats & {"execution", "persistence", "network"}):
        reasons.append("security-control disabling with corroborating behavior")
        return "malicious", "high", reasons

    if "destructive_recovery_inhibition" in strong and ev.score >= 55 and (cats & {"execution", "evasion"}):
        reasons.append("recovery-inhibition/destructive command with corroboration")
        return "malicious", "high", reasons

    if "miner_cluster" in strong and ev.score >= 45:
        reasons.append("cryptomining protocol + miner-family markers")
        return "malicious", "high", reasons

    # One strong cluster is still significant, but not enough by itself to
    # confidently call malware without additional corroboration.
    if strong or ev.score >= 35:
        return "suspicious", "medium", ["suspicious static evidence without enough independent high-risk clusters"]

    return "unknown", "low", ["insufficient independent static evidence"]

def _scan_stream(stream: BinaryIO, filename: str, *, precomputed_sha256: str | None = None) -> dict:
    ev = _Evidence()
    sha256, total, first_two, sample_entropy, stream_meta = _stream_scan(
        stream, filename, ev, precomputed_sha256=precomputed_sha256
    )

    ext = Path(filename).suffix.lower()
    script = ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".py", ".pyw"}
    if script:
        ev.add(4, "Script file", ext, "script")
    if first_two == b"MZ":
        ev.add(5, "PE executable", "Windows portable executable", "structure")

    if total > 4096 and sample_entropy > 7.45:
        ev.add(12, "High entropy", f"sample entropy={sample_entropy:.3f}", "packer")

    lname = filename.lower()
    if any(lname.endswith(x) for x in (
        ".pdf.exe", ".jpg.exe", ".jpeg.exe", ".png.exe", ".doc.exe", ".docx.exe",
        ".xls.exe", ".xlsx.exe", ".txt.exe", ".scr.exe",
    )):
        ev.add(22, "Double extension", "Executable disguised as a document/image", "evasion")

    verdict, confidence, reasons = _static_verdict(ev)
    return {
        "sha256": sha256,
        "size": total,
        "score": ev.score,
        "findings": ev.findings,
        "categories": sorted(ev.categories),
        "high_risk_tags": sorted(_derive_tags(ev)),
        "static_verdict": verdict,
        "confidence": confidence,
        "decision_reasons": reasons,
        "analysis": {
            "sample_entropy": round(sample_entropy, 3),
            **stream_meta,
        },
    }


def scan_file_path(path: str | os.PathLike[str], filename: str = "upload.bin", *, precomputed_sha256: str | None = None) -> dict:
    path = str(path)
    ev = _Evidence()

    # First perform memory-bounded streaming analysis.
    with open(path, "rb") as f:
        sha256, total, first_two, sample_entropy, stream_meta = _stream_scan(
            f, filename, ev, precomputed_sha256=precomputed_sha256
        )

    ext = Path(filename).suffix.lower()
    if ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".py", ".pyw"}:
        ev.add(4, "Script file", ext, "script")

    pe_meta = None
    pyi_meta = None
    if first_two == b"MZ":
        ev.add(5, "PE executable", "Windows portable executable", "structure")
        pe_meta = _analyze_pe(path, ev)
        pyi_meta = _analyze_pyinstaller(path, ev, stream_meta.get("pyinstaller_markers", []))

    # V4 deeper layers: PowerShell/Base64 deobfuscation, Python AST behavior,
    # ransomware correlation, loader/stager code patterns, embedded compressed
    # streams, and PyInstaller behavior correlation.  Nothing is executed.
    advanced_meta = analyze_file(
        path,
        filename,
        ev,
        pe_meta=pe_meta,
        pyinstaller_detected=bool(pyi_meta and pyi_meta.get("detected")),
    )

    if total > 4096 and sample_entropy > 7.45:
        ev.add(12, "High entropy", f"sample entropy={sample_entropy:.3f}", "packer")

    lname = filename.lower()
    if any(lname.endswith(x) for x in (
        ".pdf.exe", ".jpg.exe", ".jpeg.exe", ".png.exe", ".doc.exe", ".docx.exe",
        ".xls.exe", ".xlsx.exe", ".txt.exe", ".scr.exe",
    )):
        ev.add(22, "Double extension", "Executable disguised as a document/image", "evasion")

    verdict, confidence, reasons = _static_verdict(ev)
    analysis = {
        "sample_entropy": round(sample_entropy, 3),
        **stream_meta,
    }
    if pe_meta is not None:
        analysis["pe"] = pe_meta
    if pyi_meta is not None:
        analysis["pyinstaller"] = pyi_meta
    if advanced_meta:
        analysis["advanced"] = advanced_meta

    return {
        "sha256": sha256,
        "size": total,
        "score": ev.score,
        "findings": ev.findings,
        "categories": sorted(ev.categories),
        "high_risk_tags": sorted(_derive_tags(ev)),
        "static_verdict": verdict,
        "confidence": confidence,
        "decision_reasons": reasons,
        "analysis": analysis,
    }


def scan_bytes(data: bytes, filename: str = "upload.bin") -> dict:
    # Compatibility helper. PE structural analysis needs a file path, so bytes
    # callers receive the streaming/string analysis only.
    return _scan_stream(io.BytesIO(data), filename)


def clamav_scan_path(path: str | os.PathLike[str], filename: str = "upload.bin") -> dict | None:
    exe = shutil.which("clamscan")
    if not exe:
        return None
    try:
        p = subprocess.run(
            [exe, "--no-summary", str(path)],
            capture_output=True,
            text=True,
            timeout=45,
        )
        if p.returncode == 1:
            text = (p.stdout or p.stderr).strip()
            sig = text.rsplit(":", 1)[-1].replace("FOUND", "").strip()
            return {"malicious": True, "signature": sig or "ClamAV.Detected"}
        return {"malicious": False}
    except Exception:
        return None


def clamav_scan(data: bytes, filename: str) -> dict | None:
    suffix = Path(filename).suffix[:16]
    fd, path = tempfile.mkstemp(prefix="aegis_", suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return clamav_scan_path(path, filename)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
