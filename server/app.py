from __future__ import annotations

import asyncio
import hmac
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from auth import AuthDB, AuthError, AuthStorageError, Principal
from db import ThreatDB
from providers import MalwareBazaar, SHA256_RE
from static_scan import clamav_scan, scan_bytes
from updater import IntelUpdater

load_dotenv()

# Existing threat/signature database remains local/regeneratable on Render Free.
DB_PATH = os.getenv("AEGIS_DB", "/tmp/aegis.db")
MASTER_TOKEN = os.getenv("AEGIS_TOKEN", "change-me")

# Persistent auth/account storage lives in Turso, not Render's ephemeral filesystem.
TURSO_DATABASE_URL = os.getenv("TURSO_DATABASE_URL", "").strip()
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "").strip()
AUTH_LOCAL_DB = os.getenv("AUTH_LOCAL_DB", "").strip()  # local development only

ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", "1").strip().lower() not in {"0", "false", "no", "off"}
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_MB", "16")) * 1024 * 1024
SCAN_CONCURRENCY = max(1, min(int(os.getenv("SCAN_CONCURRENCY", "1")), 2))
scan_sem = asyncio.Semaphore(SCAN_CONCURRENCY)

# Existing Waves services.
db = ThreatDB(DB_PATH)
mb = MalwareBazaar(os.getenv("MALWAREBAZAAR_AUTH_KEY") or os.getenv("ABUSECH_AUTH_KEY"))
updater = IntelUpdater(db)

# New persistent authentication store.
auth_db = AuthDB(
    database_url=TURSO_DATABASE_URL,
    auth_token=TURSO_AUTH_TOKEN,
    local_path=AUTH_LOCAL_DB,
)


def _master_ok(token: str | None) -> bool:
    if not MASTER_TOKEN or MASTER_TOKEN == "change-me" or not token:
        return False
    return hmac.compare_digest(token, MASTER_TOKEN)


def _auth_storage_503(exc: Exception):
    raise HTTPException(503, f"Authentication storage unavailable: {exc}") from exc


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
    try:
        principal = auth_db.authenticate_api_key(token or "")
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    if not principal:
        raise HTTPException(401, "Invalid or revoked Waves API key")
    return principal


def bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(401, "Login session required")
    kind, _, token = authorization.partition(" ")
    if kind.lower() != "bearer" or not token:
        raise HTTPException(401, "Use Authorization: Bearer <session-token>")
    return token.strip()


def require_session(authorization: str | None):
    token = bearer_token(authorization)
    try:
        row = auth_db.session_user(token)
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    if not row:
        raise HTTPException(401, "Session is invalid or expired")
    return row, token


def track(principal: Principal, endpoint: str, request: Request | None = None):
    # Usage accounting is deliberately best-effort. A temporary metrics write
    # failure must not turn a successful malware lookup into an HTTP 500.
    bytes_in = 0
    if request is not None:
        raw = request.headers.get("content-length")
        try:
            bytes_in = int(raw or "0")
        except ValueError:
            bytes_in = 0
    try:
        auth_db.record_usage(principal, endpoint, bytes_in)
    except AuthStorageError:
        pass


class RegisterBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=10, max_length=128)
    display_name: str = Field(default="", max_length=80)


class LoginBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class KeyCreateBody(BaseModel):
    name: str = Field(default="Default", min_length=1, max_length=64)


class PasswordChangeBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=10, max_length=128)


class AccountDeleteBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Keep the existing local/rebuildable threat-intelligence behaviour.
    db.seed_from_file(Path(__file__).with_name("seed_signatures.txt"))

    # Turso auth failure should not destroy the existing master-key API.
    # It is reported in /health and user-key auth returns HTTP 503 until fixed.
    try:
        auth_db.init_schema()
        auth_db.cleanup_sessions()
        print(f"[Waves Auth] Persistent auth ready ({auth_db.backend}).", flush=True)
    except Exception as exc:
        auth_db.ready = False
        auth_db.last_error = str(exc)
        print(f"[Waves Auth] WARNING: {exc}", flush=True)

    task = asyncio.create_task(updater.loop())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Waves Defence Cloud", version="3.1-auth-turso", lifespan=lifespan)

cors_origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip()]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Aegis-Token", "X-File-Name"],
    )


@app.get("/")
async def root():
    return {
        "service": "Waves Defence Cloud",
        "ok": True,
        "version": "3.1-auth-turso",
        "health": "/health",
        "docs": "/docs",
        "registration": ALLOW_REGISTRATION,
        "auth_backend": auth_db.backend,
        "auth": {
            "register": "/v1/auth/register",
            "login": "/v1/auth/login",
            "api_keys": "/v1/auth/api-keys",
        },
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
        "auth": auth_db.status(check=False),
    }


# ------------------------------------------------------------------
# Account authentication
# ------------------------------------------------------------------

@app.post("/v1/auth/register", status_code=201)
async def register(body: RegisterBody):
    if not ALLOW_REGISTRATION:
        raise HTTPException(403, "Public registration is disabled")
    try:
        user = auth_db.register_user(body.email, body.password, body.display_name)
    except AuthError as exc:
        raise HTTPException(400, str(exc)) from exc
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"ok": True, "user": user}


@app.post("/v1/auth/login")
async def login(body: LoginBody):
    try:
        row = auth_db.authenticate_password(body.email, body.password)
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    if not row:
        raise HTTPException(401, "Invalid email or password")
    try:
        session, expires_at = auth_db.create_session(int(row["id"]))
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {
        "ok": True,
        "session_token": session,
        "expires_at": expires_at,
        "user": {
            "id": int(row["id"]),
            "email": row["email"],
            "display_name": row["display_name"],
        },
    }


@app.post("/v1/auth/logout")
async def logout(authorization: str | None = Header(default=None)):
    _row, token = require_session(authorization)
    try:
        auth_db.revoke_session(token)
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"ok": True}


@app.get("/v1/auth/me")
async def me(authorization: str | None = Header(default=None)):
    row, _token = require_session(authorization)
    return {
        "id": int(row["id"]),
        "email": row["email"],
        "display_name": row["display_name"],
    }


@app.post("/v1/auth/password")
async def change_password(body: PasswordChangeBody, authorization: str | None = Header(default=None)):
    row, _token = require_session(authorization)
    try:
        auth_db.change_password(int(row["id"]), body.current_password, body.new_password)
    except AuthError as exc:
        raise HTTPException(400, str(exc)) from exc
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"ok": True, "message": "Password changed. Existing login sessions were revoked."}


@app.post("/v1/auth/account/delete")
async def delete_account(body: AccountDeleteBody, authorization: str | None = Header(default=None)):
    row, _token = require_session(authorization)
    try:
        auth_db.delete_account(int(row["id"]), body.current_password)
    except AuthError as exc:
        raise HTTPException(400, str(exc)) from exc
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"ok": True, "message": "Account and API keys deleted."}


@app.post("/v1/auth/api-keys", status_code=201)
async def create_api_key(body: KeyCreateBody, authorization: str | None = Header(default=None)):
    row, _token = require_session(authorization)
    try:
        meta, raw_key = auth_db.create_api_key(int(row["id"]), body.name)
    except AuthError as exc:
        raise HTTPException(400, str(exc)) from exc
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {
        "ok": True,
        "api_key": raw_key,
        "key": meta,
        "warning": "This is the only time the complete API key will be returned. Store it safely.",
    }


@app.get("/v1/auth/api-keys")
async def list_api_keys(authorization: str | None = Header(default=None)):
    row, _token = require_session(authorization)
    try:
        keys = auth_db.list_api_keys(int(row["id"]))
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"keys": keys}


@app.delete("/v1/auth/api-keys/{key_id}")
async def revoke_api_key(key_id: int, authorization: str | None = Header(default=None)):
    row, _token = require_session(authorization)
    try:
        ok = auth_db.revoke_api_key(int(row["id"]), key_id)
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    if not ok:
        raise HTTPException(404, "Active API key not found")
    return {"ok": True}


@app.get("/v1/auth/usage")
async def usage(days: int = Query(30, ge=1, le=365), authorization: str | None = Header(default=None)):
    row, _token = require_session(authorization)
    try:
        data = auth_db.usage(int(row["id"]), days)
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"days": days, "usage": data}


# ------------------------------------------------------------------
# Normal Waves API: accepts master token OR a user API key.
# Existing C++ clients can keep using X-Aegis-Token unchanged.
# ------------------------------------------------------------------

@app.get("/v1/stats")
async def stats(request: Request, x_aegis_token: str | None = Header(default=None)):
    principal = require_api_or_master(x_aegis_token)
    track(principal, "/v1/stats", request)
    return {**db.stats(), "intel": updater.status()}


@app.get("/v1/reputation/{sha256}")
async def reputation(sha256: str, request: Request, x_aegis_token: str | None = Header(default=None)):
    principal = require_api_or_master(x_aegis_token)
    track(principal, "/v1/reputation/{sha256}", request)

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
    principal = require_api_or_master(x_aegis_token)
    track(principal, "/v1/signatures", request)
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
    principal = require_api_or_master(x_aegis_token)

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

        track(principal, "/v1/scan/file", request)
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

        verdict = "suspicious" if local["score"] >= 35 else "unknown"
        return {**local, "verdict": verdict, "source": "static-analysis"}


@app.get("/v1/url/check")
async def check_url(url: str, request: Request, x_aegis_token: str | None = Header(default=None)):
    principal = require_api_or_master(x_aegis_token)
    track(principal, "/v1/url/check", request)
    row = db.has_url(url)
    return {"url": url, "verdict": "malicious" if row else "unknown", "source": row["source"] if row else "none"}


# ------------------------------------------------------------------
# Master-only administration. User API keys can NEVER call these.
# ------------------------------------------------------------------

@app.get("/v1/admin/auth-status")
async def admin_auth_status(x_aegis_token: str | None = Header(default=None)):
    require_master(x_aegis_token)
    return auth_db.status(check=True)


@app.post("/v1/admin/update")
async def force_update(x_aegis_token: str | None = Header(default=None)):
    require_master(x_aegis_token)
    if updater.running:
        return {"ok": True, "status": "update-already-running", "intel": updater.status()}
    result = await updater.refresh_all()
    return {"ok": True, "result": result, "intel": updater.status()}


@app.get("/v1/admin/users")
async def admin_users(x_aegis_token: str | None = Header(default=None)):
    require_master(x_aegis_token)
    try:
        users = auth_db.list_users()
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"users": users}


@app.post("/v1/admin/users/{user_id}/disable")
async def admin_disable_user(user_id: int, x_aegis_token: str | None = Header(default=None)):
    require_master(x_aegis_token)
    try:
        if not auth_db.set_user_active(user_id, False):
            raise HTTPException(404, "User not found")
        auth_db.revoke_all_api_keys(user_id)
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"ok": True, "user_id": user_id, "active": False}


@app.post("/v1/admin/users/{user_id}/enable")
async def admin_enable_user(user_id: int, x_aegis_token: str | None = Header(default=None)):
    require_master(x_aegis_token)
    try:
        if not auth_db.set_user_active(user_id, True):
            raise HTTPException(404, "User not found")
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"ok": True, "user_id": user_id, "active": True}


@app.post("/v1/admin/users/{user_id}/revoke-keys")
async def admin_revoke_keys(user_id: int, x_aegis_token: str | None = Header(default=None)):
    require_master(x_aegis_token)
    try:
        if not auth_db.get_user(user_id):
            raise HTTPException(404, "User not found")
        count = auth_db.revoke_all_api_keys(user_id)
    except AuthStorageError as exc:
        _auth_storage_503(exc)
    return {"ok": True, "user_id": user_id, "revoked_keys": count}
