from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path


class ThreatDB:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=30)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=30000")
        c.execute("PRAGMA synchronous=NORMAL")
        return c

    def _init(self):
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS hashes(
                    sha256 TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    source TEXT NOT NULL,
                    inserted_at TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_hashes_first_seen ON hashes(first_seen)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_hashes_inserted_at ON hashes(inserted_at)")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS url_iocs(
                    url TEXT PRIMARY KEY,
                    first_seen TEXT,
                    source TEXT NOT NULL,
                    inserted_at TEXT NOT NULL
                )
                """
            )

    def upsert_hash(self, sha256: str, label: str, source: str,
                    first_seen: str | None = None, last_seen: str | None = None):
        self.upsert_hashes(
            [
                {
                    "sha256": sha256,
                    "label": label,
                    "source": source,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                }
            ]
        )

    def upsert_hashes(self, rows) -> int:
        now = datetime.now(timezone.utc).isoformat()
        values = []
        for row in rows:
            h = str(row.get("sha256") or "").lower().strip()
            if len(h) != 64:
                continue
            values.append(
                (
                    h,
                    row.get("label") or "Known.Malware",
                    row.get("first_seen"),
                    row.get("last_seen"),
                    row.get("source") or "ThreatFeed",
                    now,
                )
            )

        if not values:
            return 0

        with self._lock, self._conn() as c:
            c.executemany(
                """
                INSERT INTO hashes(sha256,label,first_seen,last_seen,source,inserted_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(sha256) DO UPDATE SET
                  label=CASE
                    WHEN excluded.label IS NOT NULL AND excluded.label != '' THEN excluded.label
                    ELSE hashes.label
                  END,
                  first_seen=COALESCE(hashes.first_seen,excluded.first_seen),
                  last_seen=COALESCE(excluded.last_seen,hashes.last_seen),
                  source=excluded.source,
                  inserted_at=excluded.inserted_at
                """,
                values,
            )
        return len(values)

    def seed_from_file(self, path: str | Path) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        rows = []
        try:
            for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [x.strip() for x in line.split(",", 1)]
                if len(parts) != 2 or len(parts[0]) != 64:
                    continue
                rows.append(
                    {
                        "sha256": parts[0],
                        "label": parts[1] or "Seed.KnownMalware",
                        "source": "WavesDefence.Seed",
                    }
                )
        except Exception:
            return 0
        return self.upsert_hashes(rows)

    def get_hash(self, sha256: str):
        with self._conn() as c:
            return c.execute("SELECT * FROM hashes WHERE sha256=?", (sha256.lower(),)).fetchone()

    def export_recent(self, days: int = 30):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, min(days, 365)))).isoformat()
        with self._conn() as c:
            return c.execute(
                """
                SELECT sha256,label,source,first_seen FROM hashes
                WHERE inserted_at >= ? OR first_seen >= ?
                ORDER BY inserted_at DESC
                """,
                (cutoff, cutoff[:19].replace("T", " ")),
            ).fetchall()

    def add_url(self, url: str, source: str, first_seen: str | None = None):
        self.add_urls([url], source, first_seen)

    def add_urls(self, urls, source: str, first_seen: str | None = None) -> int:
        now = datetime.now(timezone.utc).isoformat()
        values = [(str(u), first_seen, source, now) for u in urls if str(u).startswith(("http://", "https://"))]
        if not values:
            return 0
        with self._lock, self._conn() as c:
            c.executemany(
                """
                INSERT INTO url_iocs(url,first_seen,source,inserted_at) VALUES(?,?,?,?)
                ON CONFLICT(url) DO UPDATE SET
                    source=excluded.source,
                    inserted_at=excluded.inserted_at
                """,
                values,
            )
        return len(values)

    def has_url(self, url: str):
        with self._conn() as c:
            return c.execute("SELECT * FROM url_iocs WHERE url=?", (url,)).fetchone()

    def prune_dynamic(self, days: int = 60):
        """Keep the database small without deleting seed signatures.

        Dynamic feeds are refreshed frequently. Seed entries are deliberately
        retained forever. Priority-family entries are refreshed every cycle, so
        their inserted_at timestamps stay current.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(7, days))).isoformat()
        with self._lock, self._conn() as c:
            c.execute(
                "DELETE FROM hashes WHERE inserted_at < ? AND source != 'WavesDefence.Seed'",
                (cutoff,),
            )
            c.execute("DELETE FROM url_iocs WHERE inserted_at < ?", (cutoff,))

    def stats(self):
        with self._conn() as c:
            h = c.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            u = c.execute("SELECT COUNT(*) FROM url_iocs").fetchone()[0]
        return {"hashes": h, "urls": u}
