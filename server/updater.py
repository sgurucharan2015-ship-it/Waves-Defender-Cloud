from __future__ import annotations
import asyncio
import os
from datetime import datetime, timezone
from db import ThreatDB
from providers import MalwareBazaar, fetch_generic_sha256_feed, fetch_urlhaus_feed

class IntelUpdater:
    def __init__(self, db: ThreatDB):
        self.db = db
        self.mb = MalwareBazaar(os.getenv("MALWAREBAZAAR_AUTH_KEY"))
        self.hash_feed = os.getenv("MALWARE_HASH_FEED_URL")
        self.urlhaus_feed = os.getenv("URLHAUS_FEED_URL")
        self.last_update = None

    def _insert(self, rows):
        for x in rows:
            self.db.upsert_hash(x["sha256"], x.get("label") or "Known.Malware", x.get("source") or "ThreatFeed", x.get("first_seen"), x.get("last_seen"))

    async def refresh_fast(self):
        rows = await self.mb.latest_100()
        self._insert(rows)
        self.last_update = datetime.now(timezone.utc).isoformat()
        return len(rows)

    async def refresh_deep(self):
        rows = await self.mb.recent_detections(168)
        self._insert(rows)
        extra = await fetch_generic_sha256_feed(self.hash_feed)
        self._insert(extra)
        urls = await fetch_urlhaus_feed(self.urlhaus_feed)
        for u in urls: self.db.add_url(u, "URLhaus")
        self.last_update = datetime.now(timezone.utc).isoformat()
        return {"malwarebazaar": len(rows), "hash_feed": len(extra), "urlhaus": len(urls)}

    async def loop(self):
        # The 15-minute pull prevents gaps in MalwareBazaar's latest-100 stream.
        counter = 0
        while True:
            try:
                if counter % 24 == 0:  # every ~6 hours
                    await self.refresh_deep()
                else:
                    await self.refresh_fast()
            except Exception:
                pass
            counter += 1
            await asyncio.sleep(15 * 60)
