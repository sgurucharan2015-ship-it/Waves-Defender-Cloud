from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from db import ThreatDB
from providers import MalwareBazaar, SHA256_RE
from stateless_auth import Principal, StatelessAuthError, StatelessKeyManager
from static_scan import clamav_scan_path, scan_file_path
from updater import IntelUpdater

load_dotenv()

DB_PATH = os.getenv("AEGIS_DB", "/tmp/aegis.db")
MASTER_TOKEN = os.getenv("AEGIS_TOKEN", "change-me")
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_MB", "20")) * 1024 * 1024
SCAN_CONCURRENCY = max(1, min(int(os.getenv("SCAN_CONCURRENCY", "1")), 2))
scan_sem = asyncio.Semaphore(SCAN_CONCURRENCY)

# Existing Waves services remain unchanged.
db = ThreatDB(DB_PATH)
mb = MalwareBazaar(os.getenv("MALWAREBAZAAR_AUTH_KEY") or os.getenv("ABUSECH_AUTH_KEY"))
updater = IntelUpdater(db)

# Zero-database user authentication.
keys = StatelessKeyManager()


def _master_ok(token: str | None) -> bool:
    if not MASTER_TOKEN or MASTER_TOKEN == "change-me" or not token:
        return False
    return hmac.compare_digest(token, MASTER_TOKEN)


def require_master(token: str | None) -> Principal:
    if not MASTER_TOKEN or MASTER_TOKEN == "change-me":
        raise HTTPException(503, "Server master token is not configured")
    if not _master_ok(token):
        raise HTTPException(401, "Master authentication required")
    return Principal(kind="master", is_admin=True)


def require_api_or_master(token: str | None) -> Principal:
    if not MASTER_TOKEN or MASTER_TOKEN == "change-me":
        raise HTTPException(503, "Server master token is not configured")
    if _master_ok(token):
        return Principal(kind="master", is_admin=True)
    principal = keys.verify(token or "")
    if not principal:
        raise HTTPException(401, "Invalid, expired, or revoked Waves API key")
    return principal


class KeyCreateBody(BaseModel):
    name: str = Field(default="Default", min_length=1, max_length=64)
    days: int | None = Field(default=None, ge=1, le=3650)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.seed_from_file(Path(__file__).with_name("seed_signatures.txt"))
    if keys.configured():
        print("[Waves Auth] Stateless HMAC authentication ready. No auth database is used.", flush=True)
    else:
        print("[Waves Auth] WARNING: WAVES_SIGNING_SECRET is missing/too short; user API keys are disabled.", flush=True)

    task = asyncio.create_task(updater.loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Waves Defence Cloud", version="4.0-advanced-static", lifespan=lifespan)

cors_origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip()]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=[
            "Content-Type", "X-Aegis-Token", "X-File-Name",
            "X-Waves-Skip-Reputation", "X-Waves-Static-Only",
        ],
    )


@app.get("/")
async def root():
    return {
        "service": "Waves Defence Cloud",
        "ok": True,
        "version": "4.0-advanced-static",
        "health": "/health",
        "docs": "/docs",
        "auth_backend": "stateless-hmac-sha256",
        "auth_database": False,
        "create_key": "/v1/auth/create-key",
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
        "auth": keys.status(),
    }


# ------------------------------------------------------------------
# Stateless user API keys. No account, password, session or DB exists.
# ------------------------------------------------------------------

@app.post("/v1/auth/create-key", status_code=201)
async def create_key(body: KeyCreateBody):
    try:
        meta, raw_key = keys.create_key(body.name, body.days)
    except StatelessAuthError as exc:
        raise HTTPException(503 if not keys.configured() else 400, str(exc)) from exc
    return {
        "ok": True,
        "api_key": raw_key,
        "key": meta,
        "storage": "none",
        "warning": (
            "The server does not store this key anywhere. Save it now. "
            "If you lose it, create a new one."
        ),
    }


@app.get("/v1/auth/key-info")
async def key_info(x_aegis_token: str | None = Header(default=None)):
    if _master_ok(x_aegis_token):
        return {"kind": "master", "is_admin": True}
    info = keys.inspect(x_aegis_token or "")
    if not info:
        raise HTTPException(401, "Invalid, expired, or revoked Waves API key")
    return info


# Friendly retirement messages for V2 database-account routes.
@app.post("/v1/auth/register", include_in_schema=False)
@app.post("/v1/auth/login", include_in_schema=False)
@app.post("/v1/auth/api-keys", include_in_schema=False)
async def old_database_auth_retired():
    raise HTTPException(
        410,
        "Database accounts were removed in Stateless Auth V3. Use POST /v1/auth/create-key instead.",
    )


# ------------------------------------------------------------------
# Normal Waves API: accepts master token OR a signed Waves user key.
# Existing C++ clients still use X-Aegis-Token unchanged.
# ------------------------------------------------------------------

@app.get("/v1/stats")
async def stats(request: Request, x_aegis_token: str | None = Header(default=None)):
    require_api_or_master(x_aegis_token)
    return {**db.stats(), "intel": updater.status()}


@app.get("/v1/reputation/{sha256}")
async def reputation(sha256: str, request: Request, x_aegis_token: str | None = Header(default=None)):
    require_api_or_master(x_aegis_token)

    sha256 = sha256.lower()
    if not SHA256_RE.fullmatch(sha256):
        raise HTTPException(400, "Invalid SHA-256")

    row = db.get_hash(sha256)
    if row:
        return {"sha256": sha256, "verdict": "malicious", "label": row["label"], "source": row["source"]}

    live = await mb.lookup_hash(sha256)
    if live:
        db.upsert_hash(live["sha256"], live["label"], live["source"], live.get("first_seen"), live.get("last_seen"))
        return {"sha256": sha256, "verdict": "malicious", "label": live["label"], "source": live["source"]}

    return {"sha256": sha256, "verdict": "unknown", "source": "none"}


@app.get("/v1/signatures", response_class=PlainTextResponse)
async def signatures(
    request: Request,
    days: int = Query(30, ge=1, le=365),
    x_aegis_token: str | None = Header(default=None),
):
    require_api_or_master(x_aegis_token)
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
    x_waves_skip_reputation: str | None = Header(default=None),
    x_waves_static_only: str | None = Header(default=None),
):
    require_api_or_master(x_aegis_token)

    filename = x_file_name or "upload.bin"

    # X-Waves-Skip-Reputation: 1
    # Bypasses BOTH the local hash-reputation database and live MalwareBazaar
    # lookup for this request. Static analysis and optional ClamAV still run.
    skip_reputation = (
        (x_waves_skip_reputation or "").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    # X-Waves-Static-Only: 1 is the clean benchmark mode: Waves' own
    # static engine only. It skips local hash reputation, MalwareBazaar,
    # and optional ClamAV, while still performing every Waves static layer.
    static_only = (
        (x_waves_static_only or "").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    if static_only:
        skip_reputation = True

    # Reject known-oversize uploads before reading the body.
    cl = request.headers.get("content-length")
    if cl:
        try:
            if int(cl) > MAX_UPLOAD:
                raise HTTPException(
                    413,
                    f"File too large. Maximum upload is {MAX_UPLOAD // (1024 * 1024)} MB",
                )
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length")

    async with scan_sem:
        # IMPORTANT:
        # Do NOT use await request.body() here. That buffers the entire upload
        # in RAM. Stream it to /tmp in chunks and calculate SHA-256 as it arrives.
        suffix = Path(filename).suffix[:16]
        fd, tmp_path = tempfile.mkstemp(prefix="waves_scan_", suffix=suffix)
        os.close(fd)

        total = 0
        hasher = hashlib.sha256()

        try:
            print(f"[SCAN] upload starting: {filename}", flush=True)

            with open(tmp_path, "wb") as out:
                async for chunk in request.stream():
                    if not chunk:
                        continue

                    total += len(chunk)
                    if total > MAX_UPLOAD:
                        raise HTTPException(
                            413,
                            f"File too large. Maximum upload is {MAX_UPLOAD // (1024 * 1024)} MB",
                        )

                    hasher.update(chunk)
                    out.write(chunk)

            sha256 = hasher.hexdigest()
            print(
                f"[SCAN] upload complete: {filename}, "
                f"{total / (1024 * 1024):.2f} MB, sha256={sha256}",
                flush=True,
            )

            # Static analysis is synchronous/CPU work. Run it off the asyncio
            # event loop so /health and other requests remain responsive.
            print("[SCAN] static analysis starting", flush=True)
            local = await asyncio.to_thread(
                scan_file_path,
                tmp_path,
                filename,
                precomputed_sha256=sha256,
            )
            print(
                f"[SCAN] static analysis complete: score={local['score']}",
                flush=True,
            )

            if skip_reputation:
                print(
                    "[SCAN] reputation skipped by X-Waves-Skip-Reputation",
                    flush=True,
                )
            else:
                row = db.get_hash(sha256)
                if row:
                    return {
                        **local,
                        "verdict": "malicious",
                        "source": row["source"],
                        "label": row["label"],
                    }

                print("[SCAN] MalwareBazaar lookup starting", flush=True)
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
                        **local,
                        "verdict": "malicious",
                        "source": live["source"],
                        "label": live["label"],
                    }

            # If ClamAV exists, scan the existing temp file directly instead of
            # constructing another full-size in-memory copy.
            clam = None
            if static_only:
                print("[SCAN] ClamAV skipped by X-Waves-Static-Only", flush=True)
            else:
                clam = await asyncio.to_thread(
                    clamav_scan_path,
                    tmp_path,
                    filename,
                )
            if clam and clam.get("malicious"):
                return {
                    **local,
                    "verdict": "malicious",
                    "source": "ClamAV",
                    "label": clam.get("signature"),
                }

            # The advanced static analyzer can now produce a high-confidence
            # malicious verdict only when multiple independent behavior
            # categories corroborate one another. A high score alone is not
            # enough.
            verdict = local.get("static_verdict") or (
                "suspicious" if local["score"] >= 35 else "unknown"
            )
            return {
                **local,
                "verdict": verdict,
                "source": (
                    "static-analysis-high-confidence"
                    if verdict == "malicious"
                    else "static-analysis"
                ),
            }

        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass


@app.get("/v1/url/check")
async def check_url(url: str, request: Request, x_aegis_token: str | None = Header(default=None)):
    require_api_or_master(x_aegis_token)
    row = db.has_url(url)
    return {"url": url, "verdict": "malicious" if row else "unknown", "source": row["source"] if row else "none"}


# ------------------------------------------------------------------
# Master-only administration. Signed user keys can NEVER call these.
# ------------------------------------------------------------------

@app.get("/v1/admin/auth-status")
async def admin_auth_status(x_aegis_token: str | None = Header(default=None)):
    require_master(x_aegis_token)
    return keys.status()


@app.post("/v1/admin/update")
async def force_update(x_aegis_token: str | None = Header(default=None)):
    require_master(x_aegis_token)
    if updater.running:
        return {"ok": True, "status": "update-already-running", "intel": updater.status()}
    result = await updater.refresh_all()
    return {"ok": True, "result": result, "intel": updater.status()}
