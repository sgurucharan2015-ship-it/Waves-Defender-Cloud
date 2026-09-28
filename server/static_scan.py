from __future__ import annotations

import hashlib
import io
import math
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import BinaryIO

PATTERNS = [
    (b"downloadstring", 25, "PowerShell downloader"),
    (b"invoke-expression", 20, "PowerShell dynamic execution"),
    (b"frombase64string", 12, "Base64 decode"),
    (b"-executionpolicy bypass", 20, "Execution policy bypass"),
    (b"-ep bypass", 20, "Execution policy bypass"),
    (b"-windowstyle hidden", 12, "Hidden PowerShell"),
    (b"-w hidden", 12, "Hidden PowerShell"),
    (b"new-object net.webclient", 18, "WebClient downloader"),
    (b"invoke-webrequest", 12, "PowerShell web request"),
    (b"certutil -urlcache", 18, "Certutil downloader"),
    (b"mshta ", 18, "MSHTA execution"),
    (b"writeprocessmemory", 12, "Process memory writing"),
    (b"createremotethread", 15, "Remote thread creation"),
]

# Server scanning is deliberately bounded for low-memory / low-CPU hosting.
SCAN_CHUNK_BYTES = 1024 * 1024
ENTROPY_SAMPLE_BYTES = 1024 * 1024
_PATTERN_OVERLAP = max(len(p[0]) for p in PATTERNS) - 1


def entropy(data: bytes | bytearray) -> float:
    """Shannon entropy using Counter (much faster than a Python byte loop)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _scan_stream(
    stream: BinaryIO,
    filename: str,
    *,
    precomputed_sha256: str | None = None,
) -> dict:
    hasher = None if precomputed_sha256 else hashlib.sha256()
    score = 0
    findings: list[dict] = []
    total = 0
    first_two = b""
    entropy_sample = bytearray()
    tail = b""

    remaining = {needle: (pts, name) for needle, pts, name in PATTERNS}
    saw_powershell = False
    saw_hidden = False
    saw_download_or_http = False

    def add(points: int, name: str, detail: str) -> None:
        nonlocal score
        score += points
        findings.append({"name": name, "score": points, "detail": detail})

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

        # Only one chunk-sized lowercase copy exists at a time. Keep a small
        # overlap so indicators split across chunk boundaries are still found.
        low = (tail + chunk).lower()

        for needle in list(remaining):
            if needle in low:
                pts, name = remaining.pop(needle)
                add(pts, name, needle.decode("ascii", "ignore"))

        if not saw_powershell and b"powershell" in low:
            saw_powershell = True
        if not saw_hidden and b"hidden" in low:
            saw_hidden = True
        if not saw_download_or_http and (b"download" in low or b"http" in low):
            saw_download_or_http = True

        tail = low[-_PATTERN_OVERLAP:] if _PATTERN_OVERLAP else b""

    sha256 = precomputed_sha256 or (hasher.hexdigest() if hasher is not None else "")

    ext = Path(filename).suffix.lower()
    script = ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
    if script:
        add(5, "Script file", ext)
    if first_two == b"MZ":
        add(5, "PE executable", "Windows portable executable")

    e = entropy(entropy_sample)
    if total > 4096 and e > 7.45:
        add(15, "High entropy", f"entropy={e:.3f}")

    if saw_powershell and saw_hidden and saw_download_or_http:
        add(35, "Hidden downloader combination", "PowerShell + hidden + network/download behavior")

    lname = filename.lower()
    if any(
        lname.endswith(x)
        for x in (".pdf.exe", ".jpg.exe", ".png.exe", ".doc.exe", ".docx.exe", ".txt.exe")
    ):
        add(25, "Double extension", "Executable disguised as a document/image")

    return {"sha256": sha256, "score": score, "findings": findings}


def scan_file_path(
    path: str | os.PathLike[str],
    filename: str = "upload.bin",
    *,
    precomputed_sha256: str | None = None,
) -> dict:
    """Static-scan a file without loading the whole file into RAM."""
    with open(path, "rb") as f:
        return _scan_stream(f, filename, precomputed_sha256=precomputed_sha256)


def scan_bytes(data: bytes, filename: str = "upload.bin") -> dict:
    """Compatibility helper for callers that already have bytes in memory."""
    return _scan_stream(io.BytesIO(data), filename)


def clamav_scan_path(path: str | os.PathLike[str], filename: str = "upload.bin") -> dict | None:
    """Run ClamAV directly on an existing temp file; no extra full-size RAM copy."""
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
    """Backward-compatible bytes API."""
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
