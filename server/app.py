from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from dotenv import load_dotenv

from db import ThreatDB
from providers import MalwareBazaar, SHA256_RE
from static_scan import clamav_scan, scan_bytes
from updater import IntelUpdater

load_dotenv()

DB_PATH = os.getenv("AEGIS_DB", str(Path(__file__).with_name("data") / "aegis.db"))
TOKEN = os.getenv("AEGIS_TOKEN", "change-me")
# Render Free has 512 MiB RAM. Keep raw cloud uploads deliberately bounded.
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_MB", "16")) * 1024 * 1024

# Prevent several simultaneous uploaded-file scans from multiplying RAM usage.
SCAN_CONCURRENCY = max(1, min(int(os.getenv("SCAN_CONCURRENCY", "1")), 2))
scan_sem = asyncio.Semaphore(SCAN_CONCURRENCY)

db = ThreatDB(DB_PATH)
mb = MalwareBazaar(os.getenv("MALWAREBAZAAR_AUTH_KEY") or os.getenv("ABUSECH_AUTH_KEY"))
updater = IntelUpdater(db)


def auth(x_aegis_token: str | None):
    if not TOKEN or TOKEN == "change-me":
        raise HTTPException(503, "Server token is not configured")
    if x_aegis_token != TOKEN:
        raise HTTPException(401, "Invalid Aegis token")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Never block Render startup on remote feeds. The server becomes healthy first,
    # then intelligence refreshes in the background.
    db.seed_from_file(Path(__file__).with_name("seed_signatures.txt"))
    task = asyncio.create_task(updater.loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Waves Defence Cloud", version="2.0", lifespan=lifespan)


@app.get("/")
async def root():
    return {
        "service": "Waves Defence Cloud",
        "ok": True,
        "health": "/health",
        "docs": "/docs",
    }


@app.head("/")
async def root_head():
    return None


@app.get("/health")
async def health():
    return {
        "ok": True,
        "stats": db.stats(),
        "intel": updater.status(),
    }


@app.get("/v1/stats")
async def stats(x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    return {**db.stats(), "intel": updater.status()}


@app.get("/v1/reputation/{sha256}")
async def reputation(sha256: str, x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    sha256 = sha256.lower()
    if not SHA256_RE.fullmatch(sha256):
        raise HTTPException(400, "Invalid SHA-256")

    row = db.get_hash(sha256)
    if row:
        return {
            "sha256": sha256,
            "verdict": "malicious",
            "label": row["label"],
            "source": row["source"],
        }

    # Live hash reputation is a small metadata request; no malware sample is downloaded.
    live = await mb.lookup_hash(sha256)
    if live:
        db.upsert_hash(
            live["sha256"],
            live["label"],
            live["source"],
            live.get("first_seen"),
            live.get("last_seen"),
        )
        return {
            "sha256": sha256,
            "verdict": "malicious",
            "label": live["label"],
            "source": live["source"],
        }

    return {"sha256": sha256, "verdict": "unknown", "source": "none"}


@app.get("/v1/signatures", response_class=PlainTextResponse)
async def signatures(
    days: int = Query(30, ge=1, le=365),
    x_aegis_token: str | None = Header(default=None),
):
    auth(x_aegis_token)
    rows = db.export_recent(days)
    lines = ["# Waves Defence rolling known-malware SHA-256 signatures"]
    for r in rows:
        label = (r["label"] or "Known.Malware").replace("\n", " ").replace(",", "_")
        lines.append(f'{r["sha256"]},{label}')
    return "\n".join(lines) + "\n"


@app.post("/v1/scan/file")
async def scan_file(
    request: Request,
    x_file_name: str | None = Header(default="upload.bin"),
    x_aegis_token: str | None = Header(default=None),
):
    auth(x_aegis_token)

    cl = request.headers.get("content-length")
    if cl:
        try:
            if int(cl) > MAX_UPLOAD:
                raise HTTPException(413, "File too large")
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length")

    async with scan_sem:
        data = await request.body()
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, "File too large")

        local = scan_bytes(data, x_file_name or "upload.bin")
        row = db.get_hash(local["sha256"])
        if row:
            return {
                **local,
                "verdict": "malicious",
                "source": row["source"],
                "label": row["label"],
            }

        live = await mb.lookup_hash(local["sha256"])
        if live:
            db.upsert_hash(
                live["sha256"],
                live["label"],
                live["source"],
                live.get("first_seen"),
                live.get("last_seen"),
            )
            return {
                **local,
                "verdict": "malicious",
                "source": live["source"],
                "label": live["label"],
            }

        clam = clamav_scan(data, x_file_name or "upload.bin")
        if clam and clam.get("malicious"):
            return {
                **local,
                "verdict": "malicious",
                "source": "ClamAV",
                "label": clam.get("signature"),
            }

        verdict = "malicious" if local["score"] >= 80 else ("suspicious" if local["score"] >= 35 else "unknown")
        return {**local, "verdict": verdict, "source": "static-analysis"}


@app.get("/v1/url/check")
async def check_url(url: str, x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    row = db.has_url(url)
    return {
        "url": url,
        "verdict": "malicious" if row else "unknown",
        "source": row["source"] if row else "none",
    }


@app.post("/v1/admin/update")
async def force_update(x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    if updater.running:
        return {"ok": True, "status": "update-already-running", "intel": updater.status()}
    result = await updater.refresh_all()
    return {"ok": True, "result": result, "intel": updater.status()}
