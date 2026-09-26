from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path

from db import ThreatDB
from providers import (
    MALWAREBAZAAR_RECENT_SHA256,
    THREATFOX_RECENT_SHA256,
    MalwareBazaar,
    fetch_generic_sha256_feed,
    fetch_sha256_feed,
    fetch_urlhaus_feed,
)


class IntelUpdater:
    def __init__(self, db: ThreatDB):
        self.db = db
        self.mb = MalwareBazaar(os.getenv("MALWAREBAZAAR_AUTH_KEY") or os.getenv("ABUSECH_AUTH_KEY"))
        self.hash_feed = os.getenv("MALWARE_HASH_FEED_URL")
        self.urlhaus_feed = os.getenv("URLHAUS_FEED_URL")

        base = Path(__file__).resolve().parent
        self.seed_file = base / "seed_signatures.txt"
        self.priority_file = base / "priority_families.txt"

        self.recent_minutes = max(15, int(os.getenv("RECENT_REFRESH_MINUTES", "30")))
        self.priority_hours = max(3, int(os.getenv("PRIORITY_REFRESH_HOURS", "12")))
        self.priority_limit = max(25, min(int(os.getenv("PRIORITY_FAMILY_LIMIT", "100")), 300))

        self.last_update: str | None = None
        self.last_error: str | None = None
        self.running = False
        self.last_counts: dict[str, int] = {}
        self._lock = asyncio.Lock()

    def _families(self):
        if not self.priority_file.exists():
            return []
        families = []
        try:
            for raw in self.priority_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if line and not line.startswith("#"):
                    families.append(line)
        except Exception:
            return []
        return families

    def _mark_ok(self, counts: dict[str, int]):
        self.last_update = datetime.now(timezone.utc).isoformat()
        self.last_error = None
        self.last_counts = counts

    async def refresh_recent(self):
        """Refresh compact hash-only feeds. No malware samples are downloaded."""
        async with self._lock:
            self.running = True
            counts = {"malwarebazaar_recent": 0, "threatfox_recent": 0}
            try:
                mb_rows = await fetch_sha256_feed(
                    MALWAREBAZAAR_RECENT_SHA256,
                    label="MalwareBazaar.Recent",
                    source="MalwareBazaar.RecentFeed",
                    max_hashes=10000,
                )
                counts["malwarebazaar_recent"] = self.db.upsert_hashes(mb_rows)
                del mb_rows

                # ThreatFox adds another small, recent SHA-256 source. Failure is harmless.
                tf_rows = await fetch_sha256_feed(
                    THREATFOX_RECENT_SHA256,
                    label="ThreatFox.RecentMalware",
                    source="ThreatFox.RecentFeed",
                    max_hashes=10000,
                )
                counts["threatfox_recent"] = self.db.upsert_hashes(tf_rows)
                del tf_rows

                self.db.prune_dynamic(60)
                self._mark_ok(counts)
                return counts
            except Exception as exc:
                self.last_error = f"recent refresh: {type(exc).__name__}: {exc}"
                return counts
            finally:
                self.running = False

    async def refresh_priority(self):
        """Refresh a curated set of high-impact malware/ransomware families.

        Each family query is bounded (default 100 hashes) and processed one at a
        time, so even dozens of families cannot create a huge in-memory response.
        """
        async with self._lock:
            self.running = True
            inserted = 0
            families_done = 0
            try:
                if not self.mb.auth_key:
                    self._mark_ok({"priority_hashes": 0, "priority_families": 0})
                    return {"priority_hashes": 0, "priority_families": 0, "note": "No abuse.ch Auth-Key configured"}

                for family in self._families():
                    rows = await self.mb.priority_family(family, self.priority_limit)
                    inserted += self.db.upsert_hashes(rows)
                    families_done += 1
                    del rows
                    # Be polite to the community API and keep CPU/network usage gentle.
                    await asyncio.sleep(0.20)

                counts = {"priority_hashes": inserted, "priority_families": families_done}
                self._mark_ok(counts)
                return counts
            except Exception as exc:
                self.last_error = f"priority refresh: {type(exc).__name__}: {exc}"
                return {"priority_hashes": inserted, "priority_families": families_done}
            finally:
                self.running = False

    async def refresh_optional(self):
        async with self._lock:
            self.running = True
            counts = {"configured_hash_feed": 0, "urlhaus": 0}
            try:
                extra = await fetch_generic_sha256_feed(self.hash_feed, max_hashes=10000)
                counts["configured_hash_feed"] = self.db.upsert_hashes(extra)
                del extra

                urls = await fetch_urlhaus_feed(self.urlhaus_feed, max_urls=20000)
                counts["urlhaus"] = self.db.add_urls(urls, "URLhaus")
                del urls

                self._mark_ok(counts)
                return counts
            except Exception as exc:
                self.last_error = f"optional refresh: {type(exc).__name__}: {exc}"
                return counts
            finally:
                self.running = False

    async def refresh_all(self):
        # Run bounded jobs sequentially; never fan out dozens of requests at once.
        result: dict[str, object] = {}
        result["recent"] = await self.refresh_recent()
        result["priority"] = await self.refresh_priority()
        result["optional"] = await self.refresh_optional()
        return result

    async def loop(self):
        # Seed signatures are local and instant.
        self.db.seed_from_file(self.seed_file)

        # IMPORTANT: this loop is a background task. FastAPI becomes healthy first;
        # Render does not have to wait for external threat feeds during deployment.
        await asyncio.sleep(2)

        recent_ticks = 0
        priority_every = max(1, (self.priority_hours * 60) // self.recent_minutes)
        optional_every = max(1, (6 * 60) // self.recent_minutes)

        while True:
            try:
                await self.refresh_recent()

                if recent_ticks % priority_every == 0:
                    await self.refresh_priority()

                if recent_ticks % optional_every == 0:
                    await self.refresh_optional()

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_error = f"update loop: {type(exc).__name__}: {exc}"

            recent_ticks += 1
            await asyncio.sleep(self.recent_minutes * 60)

    def status(self):
        return {
            "running": self.running,
            "last_update": self.last_update,
            "last_error": self.last_error,
            "last_counts": self.last_counts,
            "recent_refresh_minutes": self.recent_minutes,
            "priority_refresh_hours": self.priority_hours,
            "priority_family_limit": self.priority_limit,
        }
