from __future__ import annotations
import csv
import io
import json
import os
import re
from typing import Any
import httpx

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

class MalwareBazaar:
    API = "https://mb-api.abuse.ch/api/v1/"
    def __init__(self, auth_key: str | None):
        self.auth_key = auth_key or ""

    async def _post(self, data: dict[str, str]) -> dict[str, Any] | None:
        if not self.auth_key:
            return None
        headers = {"Auth-Key": self.auth_key, "User-Agent": "AegisAV-Intel/1.0"}
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
                r = await client.post(self.API, data=data, headers=headers)
                r.raise_for_status()
                return r.json()
        except Exception:
            return None

    async def lookup_hash(self, sha256: str):
        obj = await self._post({"query": "get_info", "hash": sha256})
        if not obj or obj.get("query_status") != "ok" or not obj.get("data"):
            return None
        x = obj["data"][0]
        return {
            "sha256": x.get("sha256_hash", sha256).lower(),
            "label": x.get("signature") or "MalwareBazaar.KnownMalware",
            "first_seen": x.get("first_seen"),
            "last_seen": x.get("last_seen"),
            "source": "MalwareBazaar",
        }

    async def recent_detections(self, hours: int = 168):
        obj = await self._post({"query": "recent_detections", "hours": str(min(168, max(1, hours)))})
        if not obj or obj.get("query_status") != "ok":
            return []
        out = []
        for x in obj.get("data") or []:
            h = (x.get("sha256_hash") or "").lower()
            if SHA256_RE.match(h):
                out.append({
                    "sha256": h,
                    "label": x.get("signature") or "MalwareBazaar.Recent",
                    "first_seen": x.get("first_seen"),
                    "last_seen": x.get("last_seen"),
                    "source": "MalwareBazaar",
                })
        return out

    async def latest_100(self):
        obj = await self._post({"query": "get_recent", "selector": "100"})
        if not obj or obj.get("query_status") != "ok":
            return []
        out = []
        for x in obj.get("data") or []:
            h = (x.get("sha256_hash") or "").lower()
            if SHA256_RE.match(h):
                out.append({
                    "sha256": h,
                    "label": x.get("signature") or "MalwareBazaar.Recent",
                    "first_seen": x.get("first_seen"),
                    "last_seen": x.get("last_seen"),
                    "source": "MalwareBazaar",
                })
        return out

async def fetch_generic_sha256_feed(url: str | None):
    """Optional administrator-supplied feed URL. Accepts plain text/CSV; extracts SHA-256 values."""
    if not url:
        return []
    try:
        async with httpx.AsyncClient(timeout=60, follow_redirects=False) as client:
            r = await client.get(url, headers={"User-Agent": "AegisAV-Intel/1.0"})
            r.raise_for_status()
        out = []
        for line in r.text.splitlines():
            m = re.search(r"\b[0-9a-fA-F]{64}\b", line)
            if m:
                out.append({"sha256": m.group(0).lower(), "label": "Feed.KnownMalware", "source": "ConfiguredFeed"})
        return out
    except Exception:
        return []

async def fetch_urlhaus_feed(url: str | None):
    """Administrator pastes the authenticated 30-day URLhaus JSON/CSV export URL from abuse.ch."""
    if not url:
        return []
    try:
        async with httpx.AsyncClient(timeout=90, follow_redirects=False) as client:
            r = await client.get(url, headers={"User-Agent": "AegisAV-Intel/1.0"})
            r.raise_for_status()
        ctype = r.headers.get("content-type", "")
        urls = []
        if "json" in ctype or r.text.lstrip().startswith(('{','[')):
            obj = r.json()
            rows = obj if isinstance(obj, list) else obj.get("urls") or obj.get("data") or []
            for x in rows:
                if isinstance(x, str) and x.startswith(("http://","https://")):
                    urls.append(x)
                elif isinstance(x, dict):
                    u = x.get("url")
                    if u: urls.append(u)
        else:
            for row in csv.reader(io.StringIO(r.text)):
                for cell in row:
                    cell = cell.strip().strip('"')
                    if cell.startswith(("http://", "https://")):
                        urls.append(cell); break
        return list(dict.fromkeys(urls))
    except Exception:
        return []
