from __future__ import annotations
import asyncio
import hashlib
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Header, Query
from fastapi.responses import PlainTextResponse
from dotenv import load_dotenv

from db import ThreatDB
from providers import MalwareBazaar, SHA256_RE
from static_scan import scan_bytes, clamav_scan
from updater import IntelUpdater

load_dotenv()
DB_PATH = os.getenv("AEGIS_DB", str(Path(__file__).with_name("data") / "aegis.db"))
TOKEN = os.getenv("AEGIS_TOKEN", "change-me")
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_MB", "64")) * 1024 * 1024

db = ThreatDB(DB_PATH)
mb = MalwareBazaar(os.getenv("MALWAREBAZAAR_AUTH_KEY"))
updater = IntelUpdater(db)

def auth(x_aegis_token: str | None):
    if not TOKEN or TOKEN == "change-me":
        raise HTTPException(503, "Server token is not configured")
    if x_aegis_token != TOKEN:
        raise HTTPException(401, "Invalid Aegis token")

@asynccontextmanager
async def lifespan(app: FastAPI):
    try: await updater.refresh_deep()
    except Exception: pass
    task = asyncio.create_task(updater.loop())
    yield
    task.cancel()

app = FastAPI(title="AegisAV Reputation Server", version="1.0", lifespan=lifespan)

@app.get("/health")
async def health():
    return {"ok": True, "stats": db.stats(), "last_update": updater.last_update}

@app.get("/v1/stats")
async def stats(x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    return {**db.stats(), "last_update": updater.last_update}

@app.get("/v1/reputation/{sha256}")
async def reputation(sha256: str, x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    sha256 = sha256.lower()
    if not SHA256_RE.match(sha256): raise HTTPException(400, "Invalid SHA-256")
    row = db.get_hash(sha256)
    if row:
        return {"sha256": sha256, "verdict": "malicious", "label": row["label"], "source": row["source"]}
    live = await mb.lookup_hash(sha256)
    if live:
        db.upsert_hash(live["sha256"], live["label"], live["source"], live.get("first_seen"), live.get("last_seen"))
        return {"sha256": sha256, "verdict": "malicious", "label": live["label"], "source": live["source"]}
    return {"sha256": sha256, "verdict": "unknown", "source": "none"}

@app.get("/v1/signatures", response_class=PlainTextResponse)
async def signatures(days: int = Query(30, ge=1, le=365), x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    rows = db.export_recent(days)
    lines = ["# AegisAV rolling known-malware SHA-256 signatures"]
    for r in rows:
        label = (r["label"] or "Known.Malware").replace("\n", " ").replace(",", "_")
        lines.append(f'{r["sha256"]},{label}')
    return "\n".join(lines) + "\n"

@app.post("/v1/scan/file")
async def scan_file(request: Request, x_file_name: str | None = Header(default="upload.bin"), x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    cl = request.headers.get("content-length")
    if cl and int(cl) > MAX_UPLOAD: raise HTTPException(413, "File too large")
    data = await request.body()
    if len(data) > MAX_UPLOAD: raise HTTPException(413, "File too large")
    local = scan_bytes(data, x_file_name or "upload.bin")
    row = db.get_hash(local["sha256"])
    if row:
        return {**local, "verdict": "malicious", "source": row["source"], "label": row["label"]}
    live = await mb.lookup_hash(local["sha256"])
    if live:
        db.upsert_hash(live["sha256"], live["label"], live["source"], live.get("first_seen"), live.get("last_seen"))
        return {**local, "verdict": "malicious", "source": live["source"], "label": live["label"]}
    clam = clamav_scan(data, x_file_name or "upload.bin")
    if clam and clam.get("malicious"):
        return {**local, "verdict": "malicious", "source": "ClamAV", "label": clam.get("signature")}
    # Heuristics alone are intentionally not allowed to declare a file definitely malicious.
    verdict = "suspicious" if local["score"] >= 35 else "unknown"
    return {**local, "verdict": verdict, "source": "static-analysis"}

@app.get("/v1/url/check")
async def check_url(url: str, x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    row = db.has_url(url)
    return {"url": url, "verdict": "malicious" if row else "unknown", "source": row["source"] if row else "none"}

@app.post("/v1/admin/update")
async def force_update(x_aegis_token: str | None = Header(default=None)):
    auth(x_aegis_token)
    return await updater.refresh_deep()
