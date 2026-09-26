from __future__ import annotations

import hashlib
import math
import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path


SCRIPT_EXTS = {
    ".ps1", ".bat", ".cmd", ".vbs",
    ".js", ".jse", ".wsf", ".hta",
}

OFFICE_MACRO_EXTS = {
    ".doc", ".docm", ".dotm",
    ".xls", ".xlsm", ".xltm",
    ".ppt", ".pptm", ".potm",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256

    for b in data:
        counts[b] += 1

    n = len(data)

    return -sum(
        (c / n) * math.log2(c / n)
        for c in counts
        if c
    )


def any_in(data: bytes, needles: tuple[bytes, ...]) -> bool:
    return any(x in data for x in needles)


def pe_exec_entropy(data: bytes) -> tuple[bool, float, bool]:
    """Return (valid_pe, max executable-section entropy, packer-ish section)."""
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False, 0.0, False

        pe_off = struct.unpack_from("<I", data, 0x3C)[0]

        if pe_off + 24 > len(data) or data[pe_off:pe_off+4] != b"PE\0\0":
            return False, 0.0, False

        num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        sec_off = pe_off + 24 + opt_size

        max_h = 0.0
        packed_name = False

        for i in range(min(num_sections, 96)):
            off = sec_off + i * 40

            if off + 40 > len(data):
                break

            name = data[off:off+8].split(b"\0", 1)[0].lower()
            raw_size = struct.unpack_from("<I", data, off + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, off + 20)[0]
            characteristics = struct.unpack_from("<I", data, off + 36)[0]

            if any(x in name for x in (
                b"upx", b"mpress", b"aspack",
                b"petite", b"packed", b"themida",
            )):
                packed_name = True

            # IMAGE_SCN_MEM_EXECUTE
            if not (characteristics & 0x20000000):
                continue

            if raw_size <= 0 or raw_ptr >= len(data):
                continue

            chunk = data[raw_ptr:min(len(data), raw_ptr + raw_size)]

            if len(chunk) >= 512:
                max_h = max(max_h, entropy(chunk))

        return True, max_h, packed_name

    except (IndexError, struct.error, ValueError):
        return False, 0.0, False


def scan_bytes(data: bytes, filename: str = "upload.bin") -> dict:
    eicar = (
        br"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
        br"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    sha256 = hashlib.sha256(data).hexdigest()
    sample = data[:32 * 1024 * 1024]
    low = sample.lower()

    strong = 0
    behavior = 0
    weak = 0
    findings: list[dict] = []

    def add(bucket: str, points: int, name: str, detail: str) -> None:
        nonlocal strong, behavior, weak

        if bucket == "strong":
            strong += points
        elif bucket == "behavior":
            behavior += points
        else:
            weak += points

        findings.append({
            "name": name,
            "score": points,
            "detail": detail,
        })

    if eicar in data:
        return {
            "sha256": sha256,
            "score": 100,
            "findings": [{
                "name": "EICAR test file",
                "score": 100,
                "detail": "Standard EICAR antivirus test pattern",
            }],
        }

    name = Path(filename).name.lower()
    ext = Path(filename).suffix.lower()
    script = ext in SCRIPT_EXTS

    if any(name.endswith(x) for x in (
        ".pdf.exe", ".jpg.exe", ".jpeg.exe", ".png.exe",
        ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
        ".txt.exe", ".zip.exe",
    )):
        add("strong", 45, "Double extension",
            "Executable disguised as a document/image")

    downloader = any_in(low, (
        b"downloadstring",
        b"new-object net.webclient",
        b"invoke-webrequest",
        b"start-bitstransfer",
        b"certutil -urlcache",
        b"bitsadmin /transfer",
    ))

    dynamic = any_in(low, (
        b"invoke-expression",
        b"iex(",
        b"iex ",
        b"scriptblock::create",
    ))

    encoded = any_in(low, (
        b"frombase64string",
        b"-encodedcommand",
        b" -enc ",
    ))

    hidden = any_in(low, (
        b"-windowstyle hidden",
        b"-w hidden",
    ))

    bypass = any_in(low, (
        b"-executionpolicy bypass",
        b"-ep bypass",
    ))

    has_url = b"http://" in low or b"https://" in low

    if script and downloader:
        add("behavior", 12, "Script downloader", "Script downloads content")

    if script and dynamic:
        add("behavior", 12, "Dynamic script execution",
            "Script dynamically executes generated content")

    if script and encoded:
        add("weak", 8, "Encoded script content",
            "Base64 or encoded-command behavior")

    if script and hidden:
        add("weak", 6, "Hidden script execution", "Hidden execution requested")

    if script and bypass:
        add("weak", 6, "Execution policy bypass", "PowerShell bypass requested")

    if script and downloader and dynamic:
        add("strong", 35, "Download-and-execute chain",
            "Downloads and dynamically executes content")

    if script and downloader and hidden:
        add("behavior", 20, "Hidden downloader",
            "Network retrieval combined with hidden execution")

    if script and downloader and bypass:
        add("behavior", 15, "Bypass downloader",
            "Network retrieval combined with execution-policy bypass")

    if script and downloader and dynamic and encoded and hidden:
        add("strong", 45, "Obfuscated hidden downloader",
            "Download + decode + execute + hidden behavior")

    if script and len(sample) > 4096 and entropy(sample) > 7.10:
        add("weak", 8, "High script entropy", "Possible script obfuscation")

    if has_url and any_in(low, (b"mshta ", b"mshta.exe")):
        add("behavior", 35, "Remote MSHTA execution",
            "MSHTA combined with HTTP(S)")

    if has_url and any_in(low, (b"regsvr32 ", b"regsvr32.exe")):
        add("behavior", 35, "Remote Regsvr32 execution",
            "Regsvr32 combined with HTTP(S)")

    if has_url and any_in(low, (b"rundll32 ", b"rundll32.exe")):
        add("behavior", 22, "Remote Rundll32 execution",
            "Rundll32 combined with HTTP(S)")

    is_pe, max_exec_h, packed_name = pe_exec_entropy(sample)

    if is_pe:
        open_process = b"openprocess" in low
        alloc_ex = b"virtualallocex" in low
        write_mem = b"writeprocessmemory" in low
        remote_thread = b"createremotethread" in low

        injection_count = sum((
            open_process, alloc_ex, write_mem, remote_thread
        ))

        if injection_count == 4:
            add("strong", 90, "Process injection chain",
                "OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread")
        elif injection_count == 3:
            add("behavior", 40, "Probable process injection",
                "Three process-injection primitives")
        elif write_mem and remote_thread:
            add("behavior", 28, "Remote memory execution pair",
                "WriteProcessMemory + CreateRemoteThread")

        create_process = any_in(low, (b"createprocessa", b"createprocessw"))
        unmap = b"ntunmapviewofsection" in low
        set_ctx = b"setthreadcontext" in low
        resume = b"resumethread" in low

        hollow_count = sum((
            create_process, unmap, write_mem, set_ctx, resume
        ))

        if hollow_count >= 4:
            add("strong", 90, "Process hollowing chain",
                "Multiple process-hollowing primitives")
        elif hollow_count == 3:
            add("behavior", 42, "Possible process hollowing",
                "Three process-hollowing primitives")

        if b"lsass.exe" in low and b"minidumpwritedump" in low:
            add("strong", 82, "LSASS memory dump behavior",
                "LSASS + MiniDumpWriteDump")

        if b"setwindowshookex" in low and b"getasynckeystate" in low:
            add("behavior", 34, "Keyboard capture combination",
                "Keyboard hook + asynchronous key-state API")

        if max_exec_h > 7.75:
            add("weak", 8, "Very high executable-section entropy",
                f"entropy={max_exec_h:.3f}")
        elif max_exec_h > 7.45:
            add("weak", 4, "High executable-section entropy",
                f"entropy={max_exec_h:.3f}")

        if packed_name:
            add("weak", 5, "Packer-style PE section",
                "Packer-style section name")

        if b"amsiinitfailed" in low and b"amsi" in low:
            add("strong", 65, "AMSI bypass indicators",
                "Strings associated with disabling AMSI")

    if (
        data[:4] == b"\xD0\xCF\x11\xE0"
        and ext in OFFICE_MACRO_EXTS
        and any_in(low, (b"vba", b"macro", b"vbaproject"))
    ):
        add("behavior", 22, "Office macro indicators",
            "Macro-capable Office document contains VBA-related strings")

        auto_run = any_in(low, (
            b"autoopen", b"document_open", b"workbook_open"
        ))
        shell_exec = any_in(low, (
            b"powershell", b"wscript.shell", b"shell("
        ))

        if auto_run and shell_exec:
            add("behavior", 28, "Auto-running macro shell execution",
                "Macro auto-run + command execution")

    score = max(0, min(100, strong + behavior + weak))

    return {
        "sha256": sha256,
        "score": score,
        "findings": findings,
    }


def clamav_scan(data: bytes, filename: str) -> dict | None:
    exe = shutil.which("clamscan")

    if not exe:
        return None

    suffix = Path(filename).suffix[:16]
    fd, path = tempfile.mkstemp(prefix="waves_", suffix=suffix)

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)

        p = subprocess.run(
            [exe, "--no-summary", path],
            capture_output=True,
            text=True,
            timeout=45,
        )

        if p.returncode == 1:
            text = (p.stdout or p.stderr).strip()
            sig = (
                text.rsplit(":", 1)[-1]
                .replace("FOUND", "")
                .strip()
            )

            return {
                "malicious": True,
                "signature": sig or "ClamAV.Detected",
            }

        return {"malicious": False}

    except Exception:
        return None

    finally:
        try:
            os.remove(path)
        except OSError:
            pass
