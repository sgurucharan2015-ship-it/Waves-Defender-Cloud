from __future__ import annotations
import hashlib
import math
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

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

def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = [0] * 256
    for b in data: counts[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts if c)

def scan_bytes(data: bytes, filename: str = "upload.bin") -> dict:
    # EICAR is a harmless industry-standard antivirus test pattern.
    eicar = br"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    sha256 = hashlib.sha256(data).hexdigest()
    low = data[:32*1024*1024].lower()
    score = 0
    findings = []
    def add(points, name, detail):
        nonlocal score
        score += points
        findings.append({"name": name, "score": points, "detail": detail})
    if eicar in data:
        add(100, "EICAR test file", "Standard EICAR antivirus test pattern")
    ext = Path(filename).suffix.lower()
    script = ext in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta"}
    if script: add(5, "Script file", ext)
    if data[:2] == b"MZ": add(5, "PE executable", "Windows portable executable")
    e = entropy(data[:8*1024*1024])
    if len(data) > 4096 and e > 7.45: add(15, "High entropy", f"entropy={e:.3f}")
    for needle, pts, name in PATTERNS:
        if needle in low: add(pts, name, needle.decode('ascii', 'ignore'))
    if b"powershell" in low and b"hidden" in low and (b"download" in low or b"http" in low):
        add(35, "Hidden downloader combination", "PowerShell + hidden + network/download behavior")
    lname = filename.lower()
    if any(lname.endswith(x) for x in (".pdf.exe", ".jpg.exe", ".png.exe", ".doc.exe", ".docx.exe", ".txt.exe")):
        add(25, "Double extension", "Executable disguised as a document/image")
    return {"sha256": sha256, "score": score, "findings": findings}

def clamav_scan(data: bytes, filename: str) -> dict | None:
    exe = shutil.which("clamscan")
    if not exe:
        return None
    suffix = Path(filename).suffix[:16]
    fd, path = tempfile.mkstemp(prefix="aegis_", suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as f: f.write(data)
        p = subprocess.run([exe, "--no-summary", path], capture_output=True, text=True, timeout=45)
        if p.returncode == 1:
            text = (p.stdout or p.stderr).strip()
            sig = text.rsplit(":",1)[-1].replace("FOUND","").strip()
            return {"malicious": True, "signature": sig or "ClamAV.Detected"}
        return {"malicious": False}
    except Exception:
        return None
    finally:
        try: os.remove(path)
        except OSError: pass
