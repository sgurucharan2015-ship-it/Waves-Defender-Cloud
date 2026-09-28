from __future__ import annotations

"""Additional bounded, non-executing static-analysis layers for Waves Defender.

This module intentionally uses only Python's standard library.  It never imports,
executes, unmarshals, or launches content from the scanned file.
"""

import ast
import base64
import binascii
import bz2
import lzma
import mmap
import os
import re
import struct
import zlib
from pathlib import Path
from typing import Any

MB = 1024 * 1024
MAX_SCRIPT_BYTES = 12 * MB
MAX_TEXT_SCAN_BYTES = 12 * MB
MAX_B64_CANDIDATES = 24
MAX_B64_INPUT = 2 * MB
MAX_LAYER_OUTPUT = 3 * MB
MAX_LAYER_TOTAL = 12 * MB
MAX_COMPRESSED_CANDIDATES = 48
MAX_COMPRESSED_INPUT = 2 * MB
MAX_EMBEDDED_PE_HITS = 16
MAX_EP_CODE = 8192
MAX_OVERLAY_MZ_CANDIDATES = 256
MAX_OVERLAY_TEXT_BYTES = 8 * MB

_SCRIPT_EXTS = {".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".py", ".pyw"}

_HIGH_VALUE_EXT_RE = re.compile(
    r"\.(?:docx?|xlsx?|pptx?|pdf|rtf|odt|ods|jpg|jpeg|png|gif|bmp|tiff?|svg|"
    r"txt|csv|sql|db|sqlite|mdb|accdb|pst|ost|eml|zip|7z|rar|tar|gz|bak|wallet|"
    r"pem|key|cer|pfx|psd|dwg|dxf|cpp|c|h|java|py|js)\b",
    re.I,
)

_B64_RE = re.compile(rb"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{160,}={0,2})(?![A-Za-z0-9+/])")
_URL_RE = re.compile(r"https?://[^\s\x00\"'<>]{6,240}", re.I)


def _add(ev: Any, points: int, name: str, detail: str, category: str) -> None:
    ev.add(points, name, detail, category)


def _read_bounded(path: str, limit: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(limit)


def _decode_text(data: bytes) -> str:
    if not data:
        return ""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16", "replace")
        except Exception:
            pass
    # PowerShell and .NET generated scripts are often UTF-16LE without a BOM.
    sample = data[: min(len(data), 4096)]
    if sample and sample.count(b"\x00") > len(sample) // 5:
        try:
            return data.decode("utf-16le", "replace")
        except Exception:
            pass
    try:
        return data.decode("utf-8", "replace")
    except Exception:
        return data.decode("latin-1", "replace")


def _strip_powershell_comments(text: str) -> str:
    # This is deliberately conservative; it is not a full PowerShell parser.
    text = re.sub(r"<#.*?#>", " ", text, flags=re.S)
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)


def _strip_ps_string_literals(text: str) -> str:
    """Replace PowerShell single/double-quoted string contents with spaces.

    This is intentionally small and conservative, but it is enough to prevent
    inert AV-test string arrays from being mistaken for executable commands.
    """
    out: list[str] = []
    i = 0
    quote: str | None = None
    while i < len(text):
        ch = text[i]
        if quote is None:
            if ch in {"'", '"'}:
                quote = ch
                out.append(' ')
            else:
                out.append(ch)
            i += 1
            continue

        # Inside a quoted string. Backtick escapes the next character in
        # double-quoted PowerShell strings; doubled single quotes escape a
        # single quote in single-quoted strings.
        if quote == '"' and ch == '`' and i + 1 < len(text):
            out.extend('  ')
            i += 2
            continue
        if quote == "'" and ch == "'" and i + 1 < len(text) and text[i + 1] == "'":
            out.extend('  ')
            i += 2
            continue
        if ch == quote:
            quote = None
            out.append(' ')
        else:
            out.append('\n' if ch == '\n' else ' ')
        i += 1
    return ''.join(out)


def _normalize_ps(text: str) -> str:
    text = _strip_powershell_comments(text)
    text = text.replace("`", "")
    # Join the common obfuscation form: 'Inv' + 'oke' + '-Expression'.
    join_re = re.compile(r"(['\"])([^'\"\r\n]{1,80})\1\s*\+\s*(['\"])([^'\"\r\n]{1,80})\3")
    for _ in range(8):
        new = join_re.sub(lambda m: repr(m.group(2) + m.group(4)), text)
        if new == text:
            break
        text = new
    return re.sub(r"\s+", " ", text).lower()


def _bounded_zlib(data: bytes, wbits: int, max_out: int = MAX_LAYER_OUTPUT) -> bytes | None:
    try:
        obj = zlib.decompressobj(wbits)
        out = obj.decompress(data, max_out)
        if not out:
            return None
        return out[:max_out]
    except Exception:
        return None


def _bounded_lzma(data: bytes, max_out: int = MAX_LAYER_OUTPUT) -> bytes | None:
    try:
        obj = lzma.LZMADecompressor()
        out = obj.decompress(data, max_length=max_out)
        return out[:max_out] if out else None
    except Exception:
        return None


def _bounded_bz2(data: bytes, max_out: int = MAX_LAYER_OUTPUT) -> bytes | None:
    try:
        obj = bz2.BZ2Decompressor()
        out = obj.decompress(data, max_length=max_out)
        return out[:max_out] if out else None
    except Exception:
        return None


def _decompress_if_wrapped(data: bytes) -> tuple[bytes | None, str | None]:
    if data.startswith(b"\x1f\x8b"):
        return _bounded_zlib(data, 31), "gzip"
    if len(data) >= 2 and data[0] == 0x78 and data[1] in {0x01, 0x5E, 0x9C, 0xDA}:
        return _bounded_zlib(data, 15), "zlib"
    if data.startswith(b"BZh"):
        return _bounded_bz2(data), "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return _bounded_lzma(data), "xz"
    return None, None


def _looks_like_pe(data: bytes, start: int = 0) -> bool:
    try:
        if start < 0 or start + 0x40 > len(data) or data[start:start + 2] != b"MZ":
            return False
        e_lfanew = struct.unpack_from("<I", data, start + 0x3C)[0]
        pe = start + e_lfanew
        return pe >= start + 0x40 and pe + 4 <= len(data) and data[pe:pe + 4] == b"PE\x00\x00"
    except Exception:
        return False


def _scan_text_features(text: str, ev: Any, context: str) -> set[str]:
    low = text.lower()
    features: set[str] = set()

    # Downloader / execution aliases and common script behaviors.
    network_terms = (
        "invoke-webrequest", " downloadstring", "net.webclient", "system.net.webclient",
        "httpclient", "start-bitstransfer", "urlretrieve", "requests.get", "requests.post",
        "urllib.request", "socket.socket", "webrequest.create",
    )
    exec_terms = (
        "invoke-expression", " iex ", "start-process", "subprocess.popen", "subprocess.run",
        "os.system", "shell=true", "wscript.shell", "cmd.exe /c", "reflection.assembly]::load",
        "[reflection.assembly]::load", "scriptblock]::create", "scriptblock::create",
    )
    evasion_terms = (
        "-executionpolicy bypass", "-ep bypass", "-windowstyle hidden", "-w hidden",
        "-encodedcommand", " -enc ", "amsiutils", "amsiinitfailed", "set-mppreference",
        "add-mppreference -exclusion", "sc stop windefend",
    )
    compression_terms = (
        "frombase64string", "gzipstream", "deflatestream", "memorystream",
        "decompress", "base64.b64decode", "b64decode(",
    )
    memory_terms = (
        "virtualalloc", "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntcreatethreadex", "getdelegateforfunctionpointer", "marshal.copy",
        "queueuserapc", "setthreadcontext", "ntunmapviewofsection",
    )

    if any(x in low for x in network_terms) or re.search(r"(?<![\w-])(?:iwr|irm|wget|curl)(?![\w-])", low):
        features.add("network")
    if any(x in low for x in exec_terms) or re.search(r"(?<![\w-])iex(?![\w-])", low):
        features.add("dynamic_execution")
    if any(x in low for x in evasion_terms):
        features.add("evasion")
    if any(x in low for x in compression_terms):
        features.add("encoded_or_compressed")
    if any(x in low for x in memory_terms):
        features.add("memory_execution")

    if features & {"network"}:
        _add(ev, 10, "Script network/download behavior", f"network-capable script content ({context})", "network")
    if "dynamic_execution" in features:
        _add(ev, 14, "Script dynamic execution", f"dynamic code/command execution ({context})", "execution")
    if "evasion" in features:
        _add(ev, 12, "Script evasion behavior", f"hidden/bypass/AMSI-related behavior ({context})", "evasion")
    if "encoded_or_compressed" in features:
        _add(ev, 8, "Encoded/compressed script payload", f"Base64/compression primitives ({context})", "encoding")
    if "memory_execution" in features:
        _add(ev, 18, "In-memory execution primitives", f"memory/injection primitives ({context})", "injection")

    if _URL_RE.search(text):
        features.add("url")

    return features


def _scan_base64_layers(data: bytes, ev: Any, context: str) -> set[str]:
    features: set[str] = set()
    total_out = 0
    seen: set[bytes] = set()
    count = 0

    for m in _B64_RE.finditer(data):
        if count >= MAX_B64_CANDIDATES or total_out >= MAX_LAYER_TOTAL:
            break
        raw = m.group(1)
        if raw in seen:
            continue
        seen.add(raw)
        count += 1

        # Limit attacker-controlled work; decode a bounded prefix for huge blobs.
        candidate = raw[:MAX_B64_INPUT]
        candidate = candidate[: len(candidate) - (len(candidate) % 4)]
        if len(candidate) < 160:
            continue
        try:
            decoded = base64.b64decode(candidate, validate=False)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) < 64:
            continue

        decoded = decoded[:MAX_LAYER_OUTPUT]
        total_out += len(decoded)
        features.add("decoded_base64")
        _add(ev, 10, "Embedded Base64 payload decoded", f"decoded {len(decoded)} bytes ({context})", "encoding")

        text = _decode_text(decoded)
        features |= _scan_text_features(text, ev, f"decoded-{context}")

        unpacked, kind = _decompress_if_wrapped(decoded)
        if unpacked:
            total_out += len(unpacked)
            features.add("decoded_compressed")
            _add(ev, 12, "Decoded compressed payload", f"{kind}, {len(unpacked)} bytes ({context})", "encoding")
            features |= _scan_text_features(_decode_text(unpacked), ev, f"decoded-{kind}-{context}")
            if _looks_like_pe(unpacked):
                features.add("decoded_pe")
                _add(ev, 22, "Decoded embedded PE payload", f"PE recovered from {kind}/Base64 layer ({context})", "dropper")

        if _looks_like_pe(decoded):
            features.add("decoded_pe")
            _add(ev, 22, "Decoded embedded PE payload", f"PE recovered from Base64 layer ({context})", "dropper")

    if count and not features:
        features.add("base64_blob")
    return features


def _python_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _python_call_name(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


def _analyze_python(path: str, data: bytes, ev: Any) -> dict[str, Any]:
    text = _decode_text(data)
    meta: dict[str, Any] = {"parsed": False}
    try:
        tree = ast.parse(text, filename=Path(path).name)
    except Exception:
        # Obfuscated/generated Python may not parse cleanly; lexical layer still runs.
        return meta

    meta["parsed"] = True
    imports: set[str] = set()
    calls: set[str] = set()
    strings: list[str] = []
    write_modes = 0
    loops = 0
    loop_encrypt_write = False

    def subtree_call_names(node: ast.AST) -> set[str]:
        names = set()
        for x in ast.walk(node):
            if isinstance(x, ast.Call):
                names.add(_python_call_name(x.func).lower())
        return names

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.lower() for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").lower()
            imports.add(mod)
            imports.update(f"{mod}.{a.name.lower()}" for a in node.names)
        elif isinstance(node, ast.Call):
            cname = _python_call_name(node.func).lower()
            if cname:
                calls.add(cname)
            if cname == "open" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                mode = node.args[1].value.lower()
                if any(c in mode for c in ("w", "a", "x")):
                    write_modes += 1
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append(node.value)
        elif isinstance(node, (ast.For, ast.While)):
            loops += 1
            sub = subtree_call_names(node)
            has_enc = any(x.endswith(".encrypt") or x in {"fernet.encrypt", "cipher.encryptor"} for x in sub)
            has_write = any(x.endswith((".write", ".write_bytes", ".write_text", ".replace", ".rename", ".unlink")) for x in sub) or "open" in sub
            if has_enc and has_write:
                loop_encrypt_write = True

    low_imports = " ".join(sorted(imports))
    low_calls = " ".join(sorted(calls))
    all_text = "\n".join(strings).lower()

    crypto = (
        "cryptography.fernet" in low_imports
        or "fernet" in low_imports
        or any(x.endswith(".encrypt") for x in calls)
        or any(x in low_calls for x in ("cipher.encryptor", "aes.new", "chacha20poly1305"))
    )
    keygen = any("generate_key" in x or "secrets.token_bytes" in x or "os.urandom" in x for x in calls)
    enum_calls = {
        "os.walk", "os.scandir", "os.listdir", "glob.glob", "glob.iglob",
        "pathlib.path.rglob", "pathlib.path.glob", "path.rglob", "path.glob", "rglob", "glob",
    }
    enumeration = any(x in calls for x in enum_calls) or any(x.endswith((".rglob", ".glob")) for x in calls)
    write = write_modes > 0 or any(x.endswith((".write", ".write_bytes", ".write_text")) for x in calls)
    destructive = any(x.endswith((".remove", ".unlink", ".replace", ".rename")) for x in calls) or any(x in calls for x in {"os.remove", "os.unlink", "os.replace", "os.rename"})
    ext_hits = sorted({m.group(0).lower() for m in _HIGH_VALUE_EXT_RE.finditer(all_text)})
    ransom_markers = sum(1 for x in ("files have been encrypted", "your files are encrypted", "decrypt your files", "ransom", "bitcoin", "monero", ".onion") if x in all_text)

    # PyInstaller / Python stealer style behavior categories.
    py_features: set[str] = set()
    if any(x in low_imports or x in low_calls for x in ("requests", "urllib", "socket", "http.client")):
        py_features.add("network")
    if any(x in low_imports or x in low_calls for x in ("subprocess", "os.system", "ctypes", "win32api")):
        py_features.add("execution")
    if any(x in low_imports or x in all_text for x in ("pynput", "keyboard", "pyautogui", "mss")):
        py_features.add("input_capture")
    if any(x in low_imports or x in all_text for x in ("win32crypt", "browser_cookie3", "login data", "local state", "cookies.sqlite", "key4.db")):
        py_features.add("credential_access")
    if any(x in low_imports or x in low_calls for x in ("winreg", "winshell", "schtasks")):
        py_features.add("persistence")

    if crypto and write:
        _add(ev, 24, "Python file-encryption capability", "cryptographic transform + file write/overwrite logic", "ransomware")
        ev.tags.add("file_encryption_capability")
    if keygen and crypto:
        _add(ev, 4, "Encryption-key generation", "program generates encryption key material", "crypto")
    if enumeration:
        _add(ev, 14, "Recursive/bulk file enumeration", "filesystem enumeration suitable for bulk processing", "ransomware")
    if len(ext_hits) >= 4:
        _add(ev, 14, "High-value file extension targeting", f"{len(ext_hits)} document/data extension types referenced", "ransomware")
    if loop_encrypt_write:
        _add(ev, 26, "Encryption inside file-processing loop", "repeated encryption + write behavior in loop", "ransomware")
    if destructive and crypto:
        _add(ev, 14, "Encrypted-file replacement/deletion behavior", "encryption combined with replacement/delete/rename operations", "destructive")
    if ransom_markers >= 2:
        _add(ev, 20, "Ransom-note indicators", "multiple encryption/recovery/payment strings", "ransomware")
        ev.tags.add("ransom_note_cluster")

    if crypto and write and enumeration and (loop_encrypt_write or len(ext_hits) >= 4):
        ev.tags.add("ransomware_mass_encryption")
        _add(ev, 22, "Mass-encryption behavior cluster", "encryption + bulk enumeration + repeated/targeted file overwrite", "ransomware")
    if "ransomware_mass_encryption" in ev.tags and (destructive or ransom_markers >= 2):
        ev.tags.add("ransomware_destructive")

    if {"credential_access", "network"}.issubset(py_features):
        ev.tags.add("python_credential_exfil_cluster")
        _add(ev, 24, "Python credential-access + network cluster", "credential-storage access combined with network capability", "credential_access")
    if {"input_capture", "network"}.issubset(py_features):
        ev.tags.add("python_input_capture_exfil_cluster")
        _add(ev, 24, "Python input-capture + network cluster", "input-capture libraries combined with network capability", "credential_access")

    meta.update({
        "imports_seen": len(imports),
        "calls_seen": len(calls),
        "loops": loops,
        "high_value_extensions": ext_hits[:30],
        "features": sorted(py_features),
    })
    return meta


def _analyze_powershell(data: bytes, ev: Any) -> dict[str, Any]:
    text = _decode_text(data)
    full_norm = _normalize_ps(text)

    # Semantic-ish code view: comments and quoted string contents are removed.
    # Raw strings still contribute ordinary findings in the base scanner, but
    # they cannot by themselves create V4 high-risk behavior clusters.
    code_text = _strip_ps_string_literals(_strip_powershell_comments(text))
    code_norm = _normalize_ps(code_text)
    code_features = _scan_text_features(code_norm, ev, "PowerShell code")
    layer_features = _scan_base64_layers(data, ev, "PowerShell")
    constructed_meta = _scan_powershell_constructed_base64(text, ev)
    constructed_features = set(constructed_meta.get("features") or [])
    features = set(code_features) | set(layer_features) | constructed_features

    raw_has_suspicious = any(x in full_norm for x in (
        "invoke-expression", "downloadstring", "frombase64string", "virtualallocex",
        "writeprocessmemory", "createremotethread", "-executionpolicy bypass",
        "-windowstyle hidden", "set-mppreference", "vssadmin delete shadows",
    ))
    if raw_has_suspicious and not code_features:
        ev.flags.add("suppress_raw_script_combo_tags")

    code_decode = (
        "frombase64string" in code_norm
        or "-encodedcommand" in code_norm
        or re.search(r"(?<![\w-])-enc(?![\w-])", code_norm) is not None
    )
    code_exec = (
        "invoke-expression" in code_norm
        or re.search(r"(?<![\w-])iex(?![\w-])", code_norm) is not None
        or "scriptblock]::create" in code_norm
        or "scriptblock::create" in code_norm
        or "reflection.assembly]::load" in code_norm
        or "[reflection.assembly]::load" in code_norm
    )

    if code_decode:
        ev.tags.add("encoded_script_payload")

    # Obfuscation is counted only from code, not from inert quoted test strings.
    obf_count = sum(1 for x in (
        "[char]", "-join", ".replace(", "frombase64string", "gzipstream",
        "deflatestream", "scriptblock", "invoke-expression"
    ) if x in code_norm)
    if obf_count >= 3:
        _add(ev, 14, "PowerShell obfuscation cluster", f"{obf_count} independent obfuscation/dynamic-execution primitives", "evasion")
        features.add("obfuscation")

    huge_b64 = any(len(m.group(1)) >= 8192 for m in _B64_RE.finditer(data[:MAX_SCRIPT_BYTES]))
    if huge_b64 and code_decode:
        _add(ev, 18, "Large encoded PowerShell payload", "large Base64 blob combined with active decode/encoded-command logic", "encoding")
        ev.tags.add("encoded_script_payload")

    # Decoded content is only elevated to a malicious chain when the outer
    # script actively decodes/executes it. Merely storing suspicious-looking
    # Base64 data remains suspicious rather than malicious.
    if code_decode and code_exec and ("decoded_base64" in features or constructed_meta.get("decoded_candidates")):
        if features & {"dynamic_execution", "network", "memory_execution", "evasion", "decoded_pe"}:
            ev.tags.add("powershell_encoded_payload_chain")

    # V5 fallback for very large encoded droppers whose payload is deliberately
    # split/obfuscated enough that a bounded decoder cannot fully reconstruct it.
    # Active decode + active execution + a very large encoded body is itself a
    # meaningful chain, but inert string-only AV tests are still suppressed.
    if code_decode and code_exec and huge_b64 and len(data) >= 128 * 1024:
        ev.tags.add("powershell_encoded_payload_chain")
        _add(ev, 24, "Large active encoded PowerShell chain", "active Base64 decode + dynamic execution in a large script", "execution")
    if code_exec and {"network", "dynamic_execution"}.issubset(code_features) and (
        "evasion" in code_features or "encoded_or_compressed" in code_features or "obfuscation" in features
    ):
        ev.tags.add("powershell_download_execute_chain")

    # PowerShell ransomware/static file-encryption logic: use executable code
    # view for operations, but keep literal extension/ransom-note strings as
    # useful targeting evidence.
    crypto = any(x in code_norm for x in (
        "aescryptoserviceprovider", "aesmanaged", "rijndaelmanaged", "createencryptor(",
        "cryptostream", "system.security.cryptography.aes", "[security.cryptography.aes]",
    ))
    enumeration = ("get-childitem" in code_norm and "-recurse" in code_norm) or re.search(r"(?<![\w-])gci\s+[^\r\n]{0,120}(?:-r|-recurse)", code_norm) is not None
    write = any(x in code_norm for x in ("writeallbytes", "set-content", "[io.file]::writeallbytes", "move-item", "rename-item"))
    destructive = any(x in code_norm for x in ("remove-item", "del ", "erase ", "clear-content"))
    ext_hits = sorted({m.group(0).lower() for m in _HIGH_VALUE_EXT_RE.finditer(full_norm)})
    ransom_count = sum(1 for x in ("files have been encrypted", "your files are encrypted", "decrypt your files", "bitcoin", "monero", ".onion") if x in full_norm)

    if crypto and write:
        _add(ev, 24, "PowerShell file-encryption capability", "cryptographic encryption + file write logic", "ransomware")
        ev.tags.add("file_encryption_capability")
    if enumeration:
        _add(ev, 14, "Recursive PowerShell file enumeration", "Get-ChildItem/gci recursion", "ransomware")
    if len(ext_hits) >= 4:
        _add(ev, 14, "High-value file extension targeting", f"{len(ext_hits)} document/data extension types referenced", "ransomware")
    if crypto and write and enumeration:
        ev.tags.add("ransomware_mass_encryption")
        _add(ev, 24, "Mass-encryption behavior cluster", "encryption + recursive enumeration + file replacement/write", "ransomware")
    if "ransomware_mass_encryption" in ev.tags and (destructive or ransom_count >= 2):
        ev.tags.add("ransomware_destructive")

    return {
        "normalized_chars": len(full_norm),
        "semantic_code_chars": len(code_norm),
        "features": sorted(features),
        "code_features": sorted(code_features),
        "high_value_extensions": ext_hits[:30],
        "large_base64": huge_b64,
        "active_base64_decode": code_decode,
        "active_dynamic_execution": code_exec,
        "constructed_base64": constructed_meta,
    }


def _find_valid_embedded_pes(data: bytes, start_at: int = 1) -> list[int]:
    hits: list[int] = []
    pos = max(1, start_at)
    while len(hits) < MAX_EMBEDDED_PE_HITS:
        pos = data.find(b"MZ", pos)
        if pos < 0:
            break
        if _looks_like_pe(data, pos):
            hits.append(pos)
        pos += 2
    return hits


def _scan_overlay_deep(path: str, pe_meta: dict[str, Any], ev: Any) -> dict[str, Any]:
    """Inspect the *entire* PE overlay without executing or loading it.

    V4 only inspected a bounded prefix for some operations.  V5 walks the
    complete overlay with mmap, validates embedded PE headers where possible,
    samples text throughout the overlay, and correlates the result with the
    outer loader's imports/TLS/evasion profile.
    """
    size = os.path.getsize(path)
    overlay_size = int(pe_meta.get("overlay_size") or 0)
    overlay_start = int(pe_meta.get("overlay_start") or max(0, size - overlay_size))
    if overlay_size <= 0 or overlay_start < 0 or overlay_start >= size:
        return {"overlay_scanned": False}

    ratio = overlay_size / max(1, size)
    mz_candidates = 0
    valid_pes: list[int] = []
    installer_markers: set[str] = set()
    overlay_features: set[str] = set()
    archive_types: set[str] = set()
    sampled = 0

    import_groups = pe_meta.get("suspicious_imports") or {}
    resolver_imports = set(import_groups.get("resolver") or [])
    evasion_imports = set(import_groups.get("evasion") or [])
    filesystem_imports = set(import_groups.get("filesystem") or [])
    tls_present = bool(pe_meta.get("tls_present"))
    signed = bool(pe_meta.get("authenticode_present"))

    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        # Search every byte of the overlay for candidate nested PE images.
        pos = overlay_start
        while mz_candidates < MAX_OVERLAY_MZ_CANDIDATES and len(valid_pes) < MAX_EMBEDDED_PE_HITS:
            pos = mm.find(b"MZ", pos, size)
            if pos < 0:
                break
            mz_candidates += 1
            if _looks_like_pe(mm, pos):
                valid_pes.append(pos)
            pos += 2

        # Identify common benign/self-extracting container technology.  This
        # doesn't make a file benign; it simply stops container structure alone
        # from being promoted to malware.
        marker_map = {
            b"Nullsoft": "NSIS",
            b"Inno Setup": "Inno Setup",
            b"InstallShield": "InstallShield",
            b"7-Zip": "7-Zip/SFX",
            b"WinRAR SFX": "WinRAR SFX",
            b"SFX module": "SFX",
        }
        # Archive signatures in the overlay are also reported as structure.
        sigs = {
            b"PK\x03\x04": "zip",
            b"7z\xbc\xaf\x27\x1c": "7z",
            b"Rar!\x1a\x07": "rar",
            b"MSCF": "cab",
        }
        for sig, label in sigs.items():
            if mm.find(sig, overlay_start, size) >= 0:
                archive_types.add(label)
        for marker, label in marker_map.items():
            if mm.find(marker, overlay_start, size) >= 0:
                installer_markers.add(label)

        # Sample text across the complete overlay instead of reading one fixed
        # prefix.  At most MAX_OVERLAY_TEXT_BYTES are copied in total.
        if overlay_size:
            sample_budget = min(MAX_OVERLAY_TEXT_BYTES, overlay_size)
            chunk = 512 * 1024
            if sample_budget <= chunk:
                offsets = [overlay_start]
            else:
                count = max(2, sample_budget // chunk)
                span = max(1, overlay_size - chunk)
                offsets = [overlay_start + int(span * i / max(1, count - 1)) for i in range(count)]
            seen_offsets: set[int] = set()
            for off in offsets:
                off = max(overlay_start, min(off, max(overlay_start, size - chunk)))
                if off in seen_offsets or sampled >= sample_budget:
                    continue
                seen_offsets.add(off)
                take = min(chunk, sample_budget - sampled, size - off)
                if take <= 0:
                    continue
                blob = bytes(mm[off:off + take])
                sampled += len(blob)
                txt = _decode_text(blob)
                overlay_features |= _scan_text_features(txt, ev, "PE overlay deep sample")
                pycats = _python_blob_categories(blob)
                if pycats:
                    overlay_features.update(f"python:{x}" for x in pycats)

    huge_overlay = overlay_size >= 4 * MB and ratio >= 0.50
    outer_loader = bool(resolver_imports) or "dynamic_resolver_stager" in ev.tags
    outer_evasion = tls_present or bool(evasion_imports) or "dynamic_resolver_stager" in ev.tags
    operational = bool(set(ev.categories) & {"network", "filesystem", "execution", "injection", "credential_access"})
    common_installer = bool(installer_markers)

    if valid_pes:
        _add(ev, 28, "Validated executable payload in overlay", f"{len(valid_pes)} valid nested PE image(s) found across full overlay", "dropper")
        if outer_loader and outer_evasion:
            ev.tags.add("validated_embedded_pe_dropper")
            _add(ev, 24, "Embedded-PE loader/dropper cluster", "validated nested executable + resolver/loader + evasion/TLS evidence", "loader")

    # Some loaders deliberately corrupt, encrypt, or wrap the inner PE, so a
    # literal MZ marker may be present without a currently parseable PE header.
    # Promote only when several independent outer-loader conditions agree and
    # the file does NOT identify as a common installer/SFX container.
    if huge_overlay and mz_candidates and outer_loader and outer_evasion and operational and not common_installer and not signed:
        ev.tags.add("opaque_overlay_dropper_cluster")
        _add(
            ev,
            34,
            "Opaque overlay loader/dropper cluster",
            f"overlay={overlay_size} bytes ({ratio:.1%}), MZ candidates={mz_candidates}, resolver/evasion + operational evidence",
            "dropper",
        )

    if huge_overlay and (valid_pes or mz_candidates >= 1) and outer_loader and outer_evasion and operational:
        ev.tags.add("multi_stage_loader_cluster")
        _add(ev, 18, "Multi-stage loader structure", "large appended payload/container + dynamic resolution/evasion + operational evidence", "loader")

    if archive_types:
        _add(ev, 2, "Overlay archive/container data", ", ".join(sorted(archive_types)), "structure")
    if installer_markers:
        _add(ev, 0, "Installer/SFX marker", ", ".join(sorted(installer_markers)), "structure")

    return {
        "overlay_scanned": True,
        "overlay_start": overlay_start,
        "overlay_size": overlay_size,
        "overlay_ratio": round(ratio, 4),
        "mz_candidates": mz_candidates,
        "valid_embedded_pe_offsets": valid_pes,
        "archive_types": sorted(archive_types),
        "installer_markers": sorted(installer_markers),
        "sampled_text_bytes": sampled,
        "overlay_features": sorted(overlay_features),
        "outer_loader": outer_loader,
        "outer_evasion": outer_evasion,
        "operational_evidence": operational,
    }


def _scan_powershell_constructed_base64(text: str, ev: Any) -> dict[str, Any]:
    """Recover common PowerShell Base64 assembled from quoted fragments."""
    # One long quoted string OR several quoted Base64 fragments joined by +.
    quoted = re.compile(r"(['\"])([A-Za-z0-9+/=]{48,})\1")
    fragments = [(m.start(), m.end(), m.group(2)) for m in quoted.finditer(text)]
    candidates: list[str] = []
    i = 0
    while i < len(fragments):
        start, end, val = fragments[i]
        joined = val
        j = i + 1
        last_end = end
        while j < len(fragments):
            nstart, nend, nval = fragments[j]
            between = text[last_end:nstart]
            if len(between) > 96 or "+" not in between or re.sub(r"[\s+()]", "", between):
                break
            joined += nval
            last_end = nend
            j += 1
        if len(joined) >= 160:
            candidates.append(joined)
        i = max(i + 1, j)

    decoded = 0
    features: set[str] = set()
    for val in sorted(candidates, key=len, reverse=True)[:16]:
        raw = val.encode("ascii", "ignore")
        raw = raw[:MAX_B64_INPUT]
        raw = raw[: len(raw) - (len(raw) % 4)]
        if len(raw) < 160:
            continue
        try:
            out = base64.b64decode(raw, validate=False)[:MAX_LAYER_OUTPUT]
        except Exception:
            continue
        if len(out) < 64:
            continue
        decoded += 1
        _add(ev, 12, "Constructed PowerShell Base64 decoded", f"decoded {len(out)} bytes from quoted/concatenated fragments", "encoding")
        features |= _scan_text_features(_decode_text(out), ev, "constructed-Base64")
        unpacked, kind = _decompress_if_wrapped(out)
        if unpacked:
            _add(ev, 12, "Constructed Base64 compressed layer decoded", f"{kind}, {len(unpacked)} bytes", "encoding")
            features |= _scan_text_features(_decode_text(unpacked), ev, f"constructed-{kind}")
            if _looks_like_pe(unpacked):
                features.add("decoded_pe")
                _add(ev, 24, "PowerShell decoded PE payload", f"valid PE recovered from constructed Base64/{kind}", "dropper")
        elif _looks_like_pe(out):
            features.add("decoded_pe")
            _add(ev, 24, "PowerShell decoded PE payload", "valid PE recovered from constructed Base64", "dropper")
    return {"decoded_candidates": decoded, "features": sorted(features)}


def _minimal_pe_layout(data: bytes) -> dict[str, Any] | None:
    try:
        if not _looks_like_pe(data):
            return None
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        coff = pe + 4
        machine, nsec, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        ep_rva = struct.unpack_from("<I", data, opt + 16)[0]
        sec_table = opt + opt_size
        sections = []
        ep_off = None
        for i in range(min(nsec, 32)):
            off = sec_table + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
            vs, va, rs, rp = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            sections.append((name, vs, va, rs, rp, chars))
            if va <= ep_rva < va + max(vs, rs) and rp < len(data):
                ep_off = rp + (ep_rva - va)
        return {"machine": machine, "magic": magic, "entry_point_rva": ep_rva, "entry_point_offset": ep_off, "sections": sections}
    except Exception:
        return None


def _analyze_pe_loader(path: str, pe_meta: dict[str, Any], ev: Any) -> dict[str, Any]:
    size = os.path.getsize(path)
    data = _read_bounded(path, min(max(MAX_TEXT_SCAN_BYTES, MAX_EP_CODE), size))
    layout = _minimal_pe_layout(data)
    if not layout:
        return {"status": "not-parsed"}

    imports = int(pe_meta.get("import_count") or 0)
    sections = int(pe_meta.get("sections") or 0)
    signed = bool(pe_meta.get("authenticode_present"))
    ep_off = layout.get("entry_point_offset")
    ep = b""
    if isinstance(ep_off, int) and 0 <= ep_off < len(data):
        ep = data[ep_off: ep_off + MAX_EP_CODE]

    low = data.lower()
    resolver_strings = [x for x in (b"getprocaddress", b"loadlibrarya", b"loadlibraryw", b"ldrgetprocedureaddress", b"ldrloaddll") if x in low]
    if resolver_strings:
        _add(ev, 10, "Dynamic API resolver primitives", ", ".join(x.decode() for x in resolver_strings[:5]), "loader")

    # Common PEB access forms used by importless shellcode/loaders.
    peb_x86 = (
        b"\x64\xa1\x30\x00\x00\x00" in ep
        or re.search(rb"\x64\x8b[\x00-\xff]{1,3}\x30", ep[:2048], re.S) is not None
    )
    peb_x64 = (
        b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00" in ep
        or b"\x65\x48\x8b\x0c\x25\x60\x00\x00\x00" in ep
        or re.search(rb"\x65\x48\x8b[\x00-\xff]{1,4}\x60\x00\x00\x00", ep[:2048], re.S) is not None
    )
    peb_access = peb_x86 or peb_x64
    if peb_access:
        _add(ev, 22, "PEB-based loader/API resolution", "entry-point code accesses process environment structures", "loader")

    syscall_count = ep.count(b"\x0f\x05") + ep.count(b"\x0f\x34") + ep.count(b"\xcd\x2e")
    if syscall_count:
        _add(ev, 14, "Direct/native syscall pattern", f"{syscall_count} syscall instruction pattern(s) near entry point", "evasion")

    # ROR-13 is a common API-hash primitive. Only score it in sparse-import code.
    api_hash_ror = any(x in ep for x in (b"\xc1\xc8\x0d", b"\xc1\xcf\x0d", b"\x41\xc1\xc8\x0d", b"\x41\xc1\xc9\x0d"))
    if api_hash_ror and imports <= 5:
        _add(ev, 12, "API-hash resolver pattern", "ROR-13 style hashing near entry point with sparse imports", "loader")

    tiny = size <= 16 * 1024 and imports <= 2 and sections <= 5 and not signed
    if tiny:
        _add(ev, 14, "Tiny sparse-import executable", f"size={size}, imports={imports}, sections={sections}", "loader")
        ev.tags.add("tiny_sparse_loader")

    if imports <= 3 and (peb_access or (resolver_strings and api_hash_ror) or (syscall_count and tiny)):
        ev.tags.add("dynamic_resolver_stager")
        _add(ev, 24, "Dynamic resolver/stager cluster", "sparse imports + loader/API-resolution code pattern", "loader")

    # Opaque packed loader profile (kept suspicious by itself).
    sec_details = pe_meta.get("section_details") or []
    high_exec = [s for s in sec_details if s.get("executable") and float(s.get("entropy") or 0) >= 7.5]
    if imports <= 1 and sections <= 2 and high_exec:
        ev.tags.add("opaque_packed_loader")
        _add(ev, 16, "Opaque packed-loader profile", "very high-entropy executable code + near-empty import table", "packer")

    # Native ransomware-like correlation from imports.  Individual filesystem
    # and crypto APIs are common; the dangerous signal is their combination.
    import_groups = pe_meta.get("suspicious_imports") or {}
    crypto_hits = set(import_groups.get("crypto") or [])
    fs_hits = set(import_groups.get("filesystem") or [])
    enum_hits = fs_hits & {"findfirstfilea", "findfirstfilew", "findnextfilea", "findnextfilew"}
    write_hits = fs_hits & {"writefile", "movefilea", "movefilew", "movefileexa", "movefileexw", "deletefilea", "deletefilew"}
    destructive_hits = fs_hits & {"deletefilea", "deletefilew", "movefileexa", "movefileexw"}
    if crypto_hits and write_hits:
        ev.tags.add("file_encryption_capability")
        _add(ev, 18, "Native file-encryption capability", "crypto imports combined with file-write/replace APIs", "ransomware")
    if crypto_hits and enum_hits and write_hits:
        ev.tags.add("ransomware_mass_encryption")
        _add(ev, 26, "Native mass-encryption behavior cluster", "file enumeration + cryptographic APIs + file overwrite/replace APIs", "ransomware")
        if destructive_hits:
            ev.tags.add("ransomware_destructive")

    embedded = _find_valid_embedded_pes(data, 1)
    if embedded:
        _add(ev, 20, "Embedded PE payload", f"{len(embedded)} additional valid PE image(s) found", "dropper")
        if "opaque_packed_loader" in ev.tags or "dynamic_resolver_stager" in ev.tags:
            ev.tags.add("embedded_payload_loader")

    return {
        "entry_point_offset": ep_off,
        "peb_loader_pattern": peb_access,
        "direct_syscall_patterns": syscall_count,
        "api_hash_ror13": api_hash_ror,
        "resolver_strings": [x.decode() for x in resolver_strings],
        "tiny_sparse_loader": tiny,
        "embedded_pe_offsets": embedded,
    }


def _python_blob_categories(data: bytes) -> set[str]:
    low = data.lower()
    categories: set[str] = set()
    token_groups = {
        "credential_access": (b"win32crypt", b"browser_cookie3", b"login data", b"local state", b"cookies.sqlite", b"key4.db", b"cryptunprotectdata"),
        "input_capture": (b"pynput", b"keylogger", b"pyautogui", b"mss", b"keyboard.hook"),
        "network": (b"requests", b"urllib", b"socket", b"discord.com/api/webhooks", b"api.telegram.org/bot", b"http.client"),
        "execution": (b"subprocess", b"os.system", b"ctypes", b"powershell", b"cmd.exe"),
        "persistence": (b"winreg", b"currentversion\\run", b"schtasks", b"startup"),
        "crypto": (b"cryptography.fernet", b"fernet", b"aes", b"chacha20", b"cryptodome"),
    }
    for cat, toks in token_groups.items():
        if any(t in low for t in toks):
            categories.add(cat)
    return categories


def _scan_compressed_streams(path: str, ev: Any) -> dict[str, Any]:
    size = os.path.getsize(path)
    if size <= 0:
        return {"streams_tested": 0, "streams_decoded": 0}

    tested = 0
    decoded = 0
    total_out = 0
    types: list[str] = []
    found_pe = False
    behavior_features: set[str] = set()
    python_categories: set[str] = set()

    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        signatures = [
            (b"\x1f\x8b", "gzip", 31),
            (b"\x78\x01", "zlib", 15),
            (b"\x78\x5e", "zlib", 15),
            (b"\x78\x9c", "zlib", 15),
            (b"\x78\xda", "zlib", 15),
            (b"BZh", "bzip2", None),
            (b"\xfd7zXZ\x00", "xz", None),
        ]
        seen_offsets: set[int] = set()
        for sig, kind, wbits in signatures:
            pos = 0
            while tested < MAX_COMPRESSED_CANDIDATES and total_out < MAX_LAYER_TOTAL:
                pos = mm.find(sig, pos)
                if pos < 0:
                    break
                if pos in seen_offsets:
                    pos += 1
                    continue
                seen_offsets.add(pos)
                tested += 1
                chunk = bytes(mm[pos: min(size, pos + MAX_COMPRESSED_INPUT)])
                out = None
                if kind in {"gzip", "zlib"}:
                    out = _bounded_zlib(chunk, int(wbits))
                elif kind == "bzip2":
                    out = _bounded_bz2(chunk)
                elif kind == "xz":
                    out = _bounded_lzma(chunk)
                if out and len(out) >= 64:
                    decoded += 1
                    total_out += len(out)
                    types.append(kind)
                    behavior_features |= _scan_text_features(_decode_text(out), ev, f"embedded-{kind}")
                    python_categories |= _python_blob_categories(out)
                    if _looks_like_pe(out):
                        found_pe = True
                        _add(ev, 22, "Compressed embedded PE payload", f"valid PE recovered from {kind} stream", "dropper")
                    # Nested Base64 is common inside script droppers.
                    behavior_features |= _scan_base64_layers(out[:MAX_LAYER_OUTPUT], ev, f"embedded-{kind}")
                pos += max(1, len(sig))

    if decoded:
        _add(ev, 8, "Embedded compressed streams", f"decoded {decoded} bounded stream(s): {', '.join(sorted(set(types)))}", "packer")
    if found_pe and ("opaque_packed_loader" in ev.tags or "dynamic_resolver_stager" in ev.tags):
        ev.tags.add("embedded_payload_loader")
    if found_pe:
        ev.tags.add("embedded_compressed_payload")

    return {
        "streams_tested": tested,
        "streams_decoded": decoded,
        "decoded_bytes": total_out,
        "types": sorted(set(types)),
        "embedded_pe": found_pe,
        "behavior_features": sorted(behavior_features),
        "python_categories": sorted(python_categories),
    }


def analyze_file(path: str, filename: str, ev: Any, *, pe_meta: dict[str, Any] | None = None, pyinstaller_detected: bool = False) -> dict[str, Any]:
    """Run advanced non-executing analysis and add evidence into ``ev``.

    The caller owns final verdict policy.  This function returns metadata only.
    """
    ext = Path(filename).suffix.lower()
    meta: dict[str, Any] = {}

    if ext in _SCRIPT_EXTS:
        data = _read_bounded(path, MAX_SCRIPT_BYTES)
        if ext in {".ps1", ".psm1", ".psd1"}:
            ps_meta = _analyze_powershell(data, ev)
            meta["powershell"] = ps_meta
            meta["script_features"] = ps_meta.get("features", [])
        else:
            text = _decode_text(data)
            generic = _scan_text_features(text, ev, "script")
            b64 = _scan_base64_layers(data, ev, "script")
            meta["script_features"] = sorted(generic | b64)
            if ext in {".py", ".pyw"}:
                meta["python"] = _analyze_python(path, data, ev)

    if pe_meta is not None:
        meta["pe_loader"] = _analyze_pe_loader(path, pe_meta, ev)
        meta["overlay_deep"] = _scan_overlay_deep(path, pe_meta, ev)
        compressed_meta = _scan_compressed_streams(path, ev)
        meta["compressed_layers"] = compressed_meta

        # PyInstaller bundles benefit from correlation across both raw CArchive
        # bytes and bounded, successfully decompressed PYZ/zlib-like streams.
        if pyinstaller_detected:
            data = _read_bounded(path, MAX_TEXT_SCAN_BYTES)
            categories = _python_blob_categories(data)
            categories.update(compressed_meta.get("python_categories") or [])
            if {"credential_access", "network"}.issubset(categories) or {"input_capture", "network"}.issubset(categories):
                ev.tags.add("pyinstaller_embedded_behavior")
                _add(ev, 26, "Suspicious embedded Python behavior cluster", ", ".join(sorted(categories)), "pyinstaller")
            elif len(categories) >= 3:
                _add(ev, 14, "Multiple embedded Python behavior categories", ", ".join(sorted(categories)), "pyinstaller")
            meta["pyinstaller_behavior_categories"] = sorted(categories)

    return meta
