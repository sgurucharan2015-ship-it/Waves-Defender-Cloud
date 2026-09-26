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
        return c

    def _init(self):
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("""
                CREATE TABLE IF NOT EXISTS hashes(
                    sha256 TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT,
                    source TEXT NOT NULL,
                    inserted_at TEXT NOT NULL
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_hashes_first_seen ON hashes(first_seen)")
            c.execute("""
                CREATE TABLE IF NOT EXISTS url_iocs(
                    url TEXT PRIMARY KEY,
                    first_seen TEXT,
                    source TEXT NOT NULL,
                    inserted_at TEXT NOT NULL
                )
            """)

    def upsert_hash(self, sha256: str, label: str, source: str,
                    first_seen: str | None = None, last_seen: str | None = None):
        sha256 = sha256.lower().strip()
        if len(sha256) != 64:
            return
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            c.execute("""
                INSERT INTO hashes(sha256,label,first_seen,last_seen,source,inserted_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(sha256) DO UPDATE SET
                  label=excluded.label,
                  first_seen=COALESCE(hashes.first_seen,excluded.first_seen),
                  last_seen=COALESCE(excluded.last_seen,hashes.last_seen),
                  source=excluded.source
            """, (sha256, label or "Known.Malware", first_seen, last_seen, source, now))

    def get_hash(self, sha256: str):
        with self._conn() as c:
            return c.execute("SELECT * FROM hashes WHERE sha256=?", (sha256.lower(),)).fetchone()

    def export_recent(self, days: int = 30):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, min(days, 365)))).isoformat()
        with self._conn() as c:
            # first_seen can be a provider's naive timestamp, so inserted_at is also accepted.
            return c.execute("""
                SELECT sha256,label,source,first_seen FROM hashes
                WHERE inserted_at >= ? OR first_seen >= ?
                ORDER BY inserted_at DESC
            """, (cutoff, cutoff[:19].replace('T',' '))).fetchall()

    def add_url(self, url: str, source: str, first_seen: str | None = None):
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            c.execute("""
                INSERT INTO url_iocs(url,first_seen,source,inserted_at) VALUES(?,?,?,?)
                ON CONFLICT(url) DO UPDATE SET source=excluded.source
            """, (url, first_seen, source, now))

    def has_url(self, url: str):
        with self._conn() as c:
            return c.execute("SELECT * FROM url_iocs WHERE url=?", (url,)).fetchone()

    def stats(self):
        with self._conn() as c:
            h = c.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
            u = c.execute("SELECT COUNT(*) FROM url_iocs").fetchone()[0]
        return {"hashes": h, "urls": u}
