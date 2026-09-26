from __future__ import annotations

import asyncio
import csv
import io
import re
from typing import Any

import httpx

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
SHA256_SEARCH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Small, hash-only/IOC feeds. These do NOT download malware samples.
MALWAREBAZAAR_RECENT_SHA256 = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
THREATFOX_RECENT_SHA256 = "https://threatfox.abuse.ch/export/csv/sha256/recent/"


def _http_timeout() -> httpx.Timeout:
    return httpx.Timeout(connect=10.0, read=35.0, write=10.0, pool=10.0)


def _http_limits() -> httpx.Limits:
    # Keep Render Free's memory/socket footprint small.
    return httpx.Limits(max_connections=3, max_keepalive_connections=1)


class MalwareBazaar:
    API = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, auth_key: str | None):
        self.auth_key = auth_key or ""

    async def _post(self, data: dict[str, str]) -> dict[str, Any] | None:
        if not self.auth_key:
            return None

        headers = {
            "Auth-Key": self.auth_key,
            "User-Agent": "WavesDefence-Intel/2.0",
        }

        # A short retry handles transient provider/network errors without hanging startup.
        for attempt in range(2):
            try:
                async with httpx.AsyncClient(
                    timeout=_http_timeout(),
                    limits=_http_limits(),
                    follow_redirects=False,
                    headers=headers,
                ) as client:
                    r = await client.post(self.API, data=data)
                    r.raise_for_status()
                    return r.json()
            except Exception:
                if attempt == 0:
                    await asyncio.sleep(1.0)
        return None

    @staticmethod
    def _samples(obj: dict[str, Any] | None, default_label: str, source: str):
        if not obj or obj.get("query_status") != "ok":
            return []

        out = []
        for x in obj.get("data") or []:
            h = (x.get("sha256_hash") or "").lower()
            if not SHA256_RE.fullmatch(h):
                continue
            out.append(
                {
                    "sha256": h,
                    "label": x.get("signature") or default_label,
                    "first_seen": x.get("first_seen"),
                    "last_seen": x.get("last_seen"),
                    "source": source,
                }
            )
        return out

    async def lookup_hash(self, sha256: str):
        obj = await self._post({"query": "get_info", "hash": sha256})
        rows = self._samples(obj, "MalwareBazaar.KnownMalware", "MalwareBazaar.Live")
        return rows[0] if rows else None

    async def latest_100(self):
        obj = await self._post({"query": "get_recent", "selector": "100"})
        return self._samples(obj, "MalwareBazaar.Recent", "MalwareBazaar.API.Recent")

    async def signature_samples(self, signature: str, limit: int = 100):
        limit = max(1, min(int(limit), 1000))
        obj = await self._post(
            {
                "query": "get_siginfo",
                "signature": signature,
                "limit": str(limit),
            }
        )
        return self._samples(
            obj,
            f"Priority.{signature}",
            "MalwareBazaar.Priority",
        )

    async def tag_samples(self, tag: str, limit: int = 100):
        limit = max(1, min(int(limit), 1000))
        obj = await self._post(
            {
                "query": "get_taginfo",
                "tag": tag,
                "limit": str(limit),
            }
        )
        return self._samples(
            obj,
            f"Priority.{tag}",
            "MalwareBazaar.Priority",
        )

    async def priority_family(self, family: str, limit: int = 100):
        # Most families are MalwareBazaar signatures. If not, try the tag index.
        rows = await self.signature_samples(family, limit)
        if rows:
            return rows
        return await self.tag_samples(family, limit)


async def fetch_sha256_feed(
    url: str | None,
    *,
    label: str,
    source: str,
    max_hashes: int = 10000,
):
    """Fetch a SHA-256-only/plain CSV feed with a hard item cap.

    The response is consumed line-by-line, so a large remote feed does not get
    copied into RAM as one giant string.
    """
    if not url:
        return []

    out = []
    try:
        async with httpx.AsyncClient(
            timeout=_http_timeout(),
            limits=_http_limits(),
            follow_redirects=False,
            headers={"User-Agent": "WavesDefence-Intel/2.0"},
        ) as client:
            async with client.stream("GET", url) as r:
                r.raise_for_status()
                async for line in r.aiter_lines():
                    if not line or line.startswith("#"):
                        continue
                    m = SHA256_SEARCH_RE.search(line)
                    if not m:
                        continue
                    out.append(
                        {
                            "sha256": m.group(0).lower(),
                            "label": label,
                            "source": source,
                        }
                    )
                    if len(out) >= max_hashes:
                        break
    except Exception:
        return []
    return out


async def fetch_generic_sha256_feed(url: str | None, max_hashes: int = 10000):
    return await fetch_sha256_feed(
        url,
        label="Feed.KnownMalware",
        source="ConfiguredFeed",
        max_hashes=max_hashes,
    )


async def fetch_urlhaus_feed(url: str | None, max_urls: int = 20000):
    """Stream an administrator-supplied URLhaus JSON/CSV/text export.

    This function intentionally caps the number of URLs retained in one update
    so a malformed or unexpectedly huge feed cannot exhaust Render Free RAM.
    """
    if not url:
        return []

    urls: list[str] = []
    seen: set[str] = set()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0),
            limits=_http_limits(),
            follow_redirects=False,
            headers={"User-Agent": "WavesDefence-Intel/2.0"},
        ) as client:
            async with client.stream("GET", url) as r:
                r.raise_for_status()
                async for line in r.aiter_lines():
                    if not line or line.startswith("#"):
                        continue

                    # CSV/text path. This is deliberately line-oriented to keep
                    # memory bounded. JSON exports should be avoided on Free tier.
                    try:
                        cells = next(csv.reader([line]))
                    except Exception:
                        cells = [line]

                    found = None
                    for cell in cells:
                        value = cell.strip().strip('"')
                        if value.startswith(("http://", "https://")):
                            found = value
                            break
                    if found and found not in seen:
                        seen.add(found)
                        urls.append(found)
                        if len(urls) >= max_urls:
                            break
    except Exception:
        return []
    return urls
