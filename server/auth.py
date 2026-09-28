from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
API_KEY_NAME_RE = re.compile(r"^[A-Za-z0-9 _.-]{1,64}$")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


@dataclass(slots=True)
class Principal:
    kind: str  # "master" or "api_key"
    user_id: int | None = None
    key_id: int | None = None
    email: str | None = None
    display_name: str | None = None
    is_admin: bool = False


class AuthError(Exception):
    pass


class AuthStorageError(Exception):
    pass


class AuthDB:
    """Persistent authentication store for Waves Defender Cloud.

    Production mode uses a remote Turso/libSQL database configured with:
      TURSO_DATABASE_URL
      TURSO_AUTH_TOKEN

    For local development only, AUTH_LOCAL_DB can point to a normal SQLite file.

    Security properties:
      * Passwords are salted PBKDF2-HMAC-SHA256 hashes.
      * Full API keys are never stored; only SHA-256 hashes and a short prefix.
      * Full login-session tokens are never stored; only SHA-256 hashes.
    """

    def __init__(
        self,
        database_url: str | None = None,
        auth_token: str | None = None,
        local_path: str | None = None,
    ):
        self.database_url = (database_url or "").strip()
        self.auth_token = (auth_token or "").strip()
        self.local_path = (local_path or "").strip()
        self._lock = threading.RLock()
        self.ready = False
        self.last_error: str | None = None

        self.password_iterations = max(
            100_000,
            min(int(os.getenv("PASSWORD_PBKDF2_ITERATIONS", "310000")), 2_000_000),
        )
        self.session_hours = max(1, min(int(os.getenv("SESSION_HOURS", "24")), 24 * 30))
        self.max_api_keys = max(1, min(int(os.getenv("MAX_API_KEYS_PER_USER", "10")), 100))

        if self.database_url:
            self.backend = "turso"
        elif self.local_path:
            self.backend = "sqlite-local"
        else:
            self.backend = "unconfigured"

    # ------------------------------------------------------------------
    # Connection/helpers
    # ------------------------------------------------------------------

    def configured(self) -> bool:
        if self.backend == "turso":
            return bool(self.database_url and self.auth_token)
        if self.backend == "sqlite-local":
            return bool(self.local_path)
        return False

    def _conn(self):
        if self.backend == "turso":
            if not self.database_url or not self.auth_token:
                raise AuthStorageError("Turso authentication database is not configured")
            try:
                import libsql  # imported lazily so local development can run without it

                return libsql.connect(
                    database=self.database_url,
                    auth_token=self.auth_token,
                )
            except Exception as exc:
                raise AuthStorageError(f"Could not connect to Turso: {exc}") from exc

        if self.backend == "sqlite-local":
            try:
                p = Path(self.local_path)
                p.parent.mkdir(parents=True, exist_ok=True)
                c = sqlite3.connect(p, timeout=30)
                c.execute("PRAGMA busy_timeout=30000")
                c.execute("PRAGMA synchronous=NORMAL")
                c.execute("PRAGMA foreign_keys=ON")
                return c
            except Exception as exc:
                raise AuthStorageError(f"Could not open local auth database: {exc}") from exc

        raise AuthStorageError(
            "Authentication database is not configured. Set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN."
        )

    @staticmethod
    def _close(conn):
        try:
            conn.close()
        except Exception:
            pass

    def _execute(self, sql: str, params: tuple[Any, ...] = ()):
        conn = self._conn()
        try:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur
        except AuthStorageError:
            raise
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            raise AuthStorageError(str(exc)) from exc
        finally:
            self._close(conn)

    def _execute_returning(
        self,
        sql: str,
        params: tuple[Any, ...],
        columns: tuple[str, ...],
    ) -> dict[str, Any] | None:
        conn = self._conn()
        try:
            cur = conn.execute(sql, params)
            raw = cur.fetchone()
            conn.commit()
            if raw is None:
                return None
            return {name: raw[i] for i, name in enumerate(columns)}
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            raise AuthStorageError(str(exc)) from exc
        finally:
            self._close(conn)

    def _one(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
        columns: tuple[str, ...] = (),
    ) -> dict[str, Any] | None:
        conn = self._conn()
        try:
            raw = conn.execute(sql, params).fetchone()
            if raw is None:
                return None
            return {name: raw[i] for i, name in enumerate(columns)}
        except Exception as exc:
            raise AuthStorageError(str(exc)) from exc
        finally:
            self._close(conn)

    def _all(
        self,
        sql: str,
        params: tuple[Any, ...] = (),
        columns: tuple[str, ...] = (),
    ) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            raws = conn.execute(sql, params).fetchall()
            return [{name: raw[i] for i, name in enumerate(columns)} for raw in raws]
        except Exception as exc:
            raise AuthStorageError(str(exc)) from exc
        finally:
            self._close(conn)

    # ------------------------------------------------------------------
    # Schema / health
    # ------------------------------------------------------------------

    def init_schema(self):
        if not self.configured():
            self.ready = False
            self.last_error = "Turso authentication database is not configured"
            raise AuthStorageError(self.last_error)

        statements = [
            """
            CREATE TABLE IF NOT EXISTS auth_users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_iterations INTEGER NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS auth_api_keys(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY(user_id) REFERENCES auth_users(id) ON DELETE CASCADE
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_auth_keys_user ON auth_api_keys(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_auth_keys_hash ON auth_api_keys(key_hash)",
            """
            CREATE TABLE IF NOT EXISTS auth_sessions(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY(user_id) REFERENCES auth_users(id) ON DELETE CASCADE
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_auth_sessions_hash ON auth_sessions(token_hash)",
            "CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id)",
            """
            CREATE TABLE IF NOT EXISTS auth_usage(
                user_id INTEGER NOT NULL,
                key_id INTEGER NOT NULL,
                day TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                requests INTEGER NOT NULL DEFAULT 0,
                bytes_in INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(user_id, key_id, day, endpoint),
                FOREIGN KEY(user_id) REFERENCES auth_users(id) ON DELETE CASCADE,
                FOREIGN KEY(key_id) REFERENCES auth_api_keys(id) ON DELETE CASCADE
            )
            """,
        ]

        conn = self._conn()
        try:
            for sql in statements:
                conn.execute(sql)
            conn.commit()
            self.ready = True
            self.last_error = None
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            self.ready = False
            self.last_error = f"Schema initialization failed: {exc}"
            raise AuthStorageError(self.last_error) from exc
        finally:
            self._close(conn)

    def ping(self) -> bool:
        try:
            row = self._one("SELECT 1", (), ("ok",))
            self.ready = bool(row and int(row["ok"]) == 1)
            if self.ready:
                self.last_error = None
            return self.ready
        except Exception as exc:
            self.ready = False
            self.last_error = str(exc)
            return False

    def status(self, check: bool = False) -> dict[str, Any]:
        if check:
            self.ping()
        return {
            "backend": self.backend,
            "configured": self.configured(),
            "ready": self.ready,
            "last_error": self.last_error,
        }

    # ------------------------------------------------------------------
    # Passwords
    # ------------------------------------------------------------------

    def _hash_password(self, password: str, salt: bytes | None = None, iterations: int | None = None):
        if not isinstance(password, str) or len(password) < 10:
            raise AuthError("Password must be at least 10 characters")
        if len(password) > 128:
            raise AuthError("Password is too long")
        salt = salt or secrets.token_bytes(16)
        iterations = int(iterations or self.password_iterations)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=32,
        )
        return digest.hex(), salt.hex(), iterations

    def _verify_password(self, password: str, row: dict[str, Any]) -> bool:
        try:
            expected = bytes.fromhex(str(row["password_hash"]))
            salt = bytes.fromhex(str(row["password_salt"]))
            actual = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                int(row["password_iterations"]),
                dklen=32,
            )
            return hmac.compare_digest(actual, expected)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def register_user(self, email: str, password: str, display_name: str = "") -> dict[str, Any]:
        email = (email or "").strip().lower()
        display_name = (display_name or "").strip()[:80]
        if not EMAIL_RE.fullmatch(email) or len(email) > 254:
            raise AuthError("Enter a valid email address")

        if self._one("SELECT id FROM auth_users WHERE email=?", (email,), ("id",)):
            raise AuthError("An account with that email already exists")

        ph, salt, iterations = self._hash_password(password)
        now = iso()
        try:
            row = self._execute_returning(
                """
                INSERT INTO auth_users(
                    email,display_name,password_hash,password_salt,
                    password_iterations,is_active,created_at
                ) VALUES(?,?,?,?,?,1,?) RETURNING id
                """,
                (email, display_name, ph, salt, iterations, now),
                ("id",),
            )
        except AuthStorageError as exc:
            if "unique" in str(exc).lower() or "constraint" in str(exc).lower():
                raise AuthError("An account with that email already exists") from exc
            raise

        if not row:
            raise AuthStorageError("User was inserted but no ID was returned")
        return {"id": int(row["id"]), "email": email, "display_name": display_name, "created_at": now}

    def authenticate_password(self, email: str, password: str) -> dict[str, Any] | None:
        email = (email or "").strip().lower()
        columns = (
            "id", "email", "display_name", "password_hash", "password_salt",
            "password_iterations", "is_active", "created_at", "last_login_at",
        )
        row = self._one(
            """
            SELECT id,email,display_name,password_hash,password_salt,
                   password_iterations,is_active,created_at,last_login_at
            FROM auth_users WHERE email=?
            """,
            (email,),
            columns,
        )
        if not row or not bool(row["is_active"]):
            hashlib.pbkdf2_hmac("sha256", b"dummy", b"0" * 16, 100_000, dklen=32)
            return None
        if not self._verify_password(password, row):
            return None
        self._execute("UPDATE auth_users SET last_login_at=? WHERE id=?", (iso(), row["id"]))
        row["last_login_at"] = iso()
        return row

    def get_user(self, user_id: int):
        return self._one(
            "SELECT id,email,display_name,is_active,created_at,last_login_at FROM auth_users WHERE id=?",
            (user_id,),
            ("id", "email", "display_name", "is_active", "created_at", "last_login_at"),
        )

    def change_password(self, user_id: int, current_password: str, new_password: str):
        row = self._one(
            """
            SELECT id,email,display_name,password_hash,password_salt,password_iterations,
                   is_active,created_at,last_login_at
            FROM auth_users WHERE id=?
            """,
            (user_id,),
            (
                "id", "email", "display_name", "password_hash", "password_salt",
                "password_iterations", "is_active", "created_at", "last_login_at",
            ),
        )
        if not row or not self._verify_password(current_password, row):
            raise AuthError("Current password is incorrect")

        ph, salt, iterations = self._hash_password(new_password)
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE auth_users SET password_hash=?,password_salt=?,password_iterations=? WHERE id=?",
                (ph, salt, iterations, user_id),
            )
            conn.execute(
                "UPDATE auth_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                (iso(), user_id),
            )
            conn.commit()
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            raise AuthStorageError(str(exc)) from exc
        finally:
            self._close(conn)

    def delete_account(self, user_id: int, current_password: str):
        row = self._one(
            """
            SELECT id,email,display_name,password_hash,password_salt,password_iterations,
                   is_active,created_at,last_login_at
            FROM auth_users WHERE id=?
            """,
            (user_id,),
            (
                "id", "email", "display_name", "password_hash", "password_salt",
                "password_iterations", "is_active", "created_at", "last_login_at",
            ),
        )
        if not row or not self._verify_password(current_password, row):
            raise AuthError("Current password is incorrect")

        conn = self._conn()
        try:
            # Delete children explicitly so this works even if a remote connection
            # does not have PRAGMA foreign_keys enabled for the current session.
            conn.execute("DELETE FROM auth_usage WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM auth_api_keys WHERE user_id=?", (user_id,))
            conn.execute("DELETE FROM auth_users WHERE id=?", (user_id,))
            conn.commit()
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            raise AuthStorageError(str(exc)) from exc
        finally:
            self._close(conn)

    # ------------------------------------------------------------------
    # Login sessions
    # ------------------------------------------------------------------

    def create_session(self, user_id: int) -> tuple[str, str]:
        raw = "waves_sess_" + _b64(secrets.token_bytes(32))
        token_hash = _sha256(raw)
        created = utcnow()
        expires = created + timedelta(hours=self.session_hours)
        self._execute(
            "INSERT INTO auth_sessions(user_id,token_hash,created_at,expires_at) VALUES(?,?,?,?)",
            (user_id, token_hash, iso(created), iso(expires)),
        )
        return raw, iso(expires)

    def session_user(self, token: str):
        if not token or not token.startswith("waves_sess_"):
            return None
        now = iso()
        token_hash = _sha256(token)
        row = self._one(
            """
            SELECT u.id,u.email,u.display_name,u.is_active,s.id,s.expires_at
            FROM auth_sessions s
            JOIN auth_users u ON u.id=s.user_id
            WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>?
            """,
            (token_hash, now),
            ("id", "email", "display_name", "is_active", "session_id", "expires_at"),
        )
        if not row or not bool(row["is_active"]):
            return None
        return row

    def revoke_session(self, token: str):
        if token:
            self._execute(
                "UPDATE auth_sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                (iso(), _sha256(token)),
            )

    def cleanup_sessions(self):
        now = iso()
        self._execute("DELETE FROM auth_sessions WHERE expires_at<? OR revoked_at IS NOT NULL", (now,))

    # ------------------------------------------------------------------
    # API keys
    # ------------------------------------------------------------------

    def create_api_key(self, user_id: int, name: str) -> tuple[dict[str, Any], str]:
        name = (name or "Default").strip()
        if not API_KEY_NAME_RE.fullmatch(name):
            raise AuthError("Key name may contain letters, numbers, spaces, dot, dash and underscore")

        count_row = self._one(
            "SELECT COUNT(*) FROM auth_api_keys WHERE user_id=? AND revoked_at IS NULL",
            (user_id,),
            ("count",),
        )
        count = int(count_row["count"] if count_row else 0)
        if count >= self.max_api_keys:
            raise AuthError(f"Maximum of {self.max_api_keys} active API keys reached")

        key_id_part = secrets.token_hex(4)
        secret = _b64(secrets.token_bytes(32))
        raw_key = f"waves_sk_{key_id_part}_{secret}"
        key_hash = _sha256(raw_key)
        prefix = f"waves_sk_{key_id_part}"
        created = iso()

        row = self._execute_returning(
            """
            INSERT INTO auth_api_keys(user_id,name,key_prefix,key_hash,created_at)
            VALUES(?,?,?,?,?) RETURNING id
            """,
            (user_id, name, prefix, key_hash, created),
            ("id",),
        )
        if not row:
            raise AuthStorageError("API key was inserted but no ID was returned")

        return (
            {
                "id": int(row["id"]),
                "name": name,
                "prefix": prefix,
                "created_at": created,
                "last_used_at": None,
                "revoked": False,
            },
            raw_key,
        )

    def authenticate_api_key(self, raw_key: str) -> Principal | None:
        if not raw_key or not raw_key.startswith("waves_sk_") or len(raw_key) > 160:
            return None
        key_hash = _sha256(raw_key)
        row = self._one(
            """
            SELECT k.id,k.user_id,k.revoked_at,u.email,u.display_name,u.is_active
            FROM auth_api_keys k
            JOIN auth_users u ON u.id=k.user_id
            WHERE k.key_hash=?
            """,
            (key_hash,),
            ("key_id", "user_id", "revoked_at", "email", "display_name", "is_active"),
        )
        if not row or row["revoked_at"] is not None or not bool(row["is_active"]):
            return None
        return Principal(
            kind="api_key",
            user_id=int(row["user_id"]),
            key_id=int(row["key_id"]),
            email=str(row["email"]),
            display_name=str(row["display_name"] or ""),
            is_admin=False,
        )

    def list_api_keys(self, user_id: int):
        rows = self._all(
            """
            SELECT id,name,key_prefix,created_at,last_used_at,revoked_at
            FROM auth_api_keys WHERE user_id=? ORDER BY id DESC
            """,
            (user_id,),
            ("id", "name", "key_prefix", "created_at", "last_used_at", "revoked_at"),
        )
        return [
            {
                "id": int(r["id"]),
                "name": r["name"],
                "prefix": r["key_prefix"],
                "created_at": r["created_at"],
                "last_used_at": r["last_used_at"],
                "revoked": r["revoked_at"] is not None,
            }
            for r in rows
        ]

    def revoke_api_key(self, user_id: int, key_id: int) -> bool:
        row = self._execute_returning(
            """
            UPDATE auth_api_keys SET revoked_at=?
            WHERE id=? AND user_id=? AND revoked_at IS NULL
            RETURNING id
            """,
            (iso(), key_id, user_id),
            ("id",),
        )
        return row is not None

    def revoke_all_api_keys(self, user_id: int) -> int:
        rows = self._all_returning(
            """
            UPDATE auth_api_keys SET revoked_at=?
            WHERE user_id=? AND revoked_at IS NULL
            RETURNING id
            """,
            (iso(), user_id),
            ("id",),
        )
        return len(rows)

    def _all_returning(
        self,
        sql: str,
        params: tuple[Any, ...],
        columns: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        conn = self._conn()
        try:
            cur = conn.execute(sql, params)
            raws = cur.fetchall()
            conn.commit()
            return [{name: raw[i] for i, name in enumerate(columns)} for raw in raws]
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            raise AuthStorageError(str(exc)) from exc
        finally:
            self._close(conn)

    # ------------------------------------------------------------------
    # Usage
    # ------------------------------------------------------------------

    def record_usage(self, principal: Principal, endpoint: str, bytes_in: int = 0):
        if principal.kind != "api_key" or principal.user_id is None or principal.key_id is None:
            return
        day = utcnow().date().isoformat()
        endpoint = (endpoint or "unknown")[:160]
        now = iso()

        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT INTO auth_usage(user_id,key_id,day,endpoint,requests,bytes_in)
                VALUES(?,?,?,?,1,?)
                ON CONFLICT(user_id,key_id,day,endpoint) DO UPDATE SET
                    requests=auth_usage.requests+1,
                    bytes_in=auth_usage.bytes_in+excluded.bytes_in
                """,
                (principal.user_id, principal.key_id, day, endpoint, max(0, int(bytes_in))),
            )
            conn.execute(
                "UPDATE auth_api_keys SET last_used_at=? WHERE id=?",
                (now, principal.key_id),
            )
            conn.commit()
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            raise AuthStorageError(str(exc)) from exc
        finally:
            self._close(conn)

    def usage(self, user_id: int, days: int = 30):
        days = max(1, min(int(days), 365))
        cutoff = (utcnow().date() - timedelta(days=days - 1)).isoformat()
        return self._all(
            """
            SELECT day,endpoint,SUM(requests),SUM(bytes_in)
            FROM auth_usage
            WHERE user_id=? AND day>=?
            GROUP BY day,endpoint
            ORDER BY day DESC, endpoint ASC
            """,
            (user_id, cutoff),
            ("day", "endpoint", "requests", "bytes_in"),
        )

    # ------------------------------------------------------------------
    # Master/admin
    # ------------------------------------------------------------------

    def list_users(self):
        rows = self._all(
            """
            SELECT u.id,u.email,u.display_name,u.is_active,u.created_at,u.last_login_at,
                   COUNT(k.id),
                   SUM(CASE WHEN k.id IS NOT NULL AND k.revoked_at IS NULL THEN 1 ELSE 0 END)
            FROM auth_users u
            LEFT JOIN auth_api_keys k ON k.user_id=u.id
            GROUP BY u.id,u.email,u.display_name,u.is_active,u.created_at,u.last_login_at
            ORDER BY u.id DESC
            """,
            (),
            (
                "id", "email", "display_name", "is_active", "created_at",
                "last_login_at", "total_keys", "active_keys",
            ),
        )
        out = []
        for r in rows:
            r["is_active"] = bool(r["is_active"])
            r["total_keys"] = int(r["total_keys"] or 0)
            r["active_keys"] = int(r["active_keys"] or 0)
            out.append(r)
        return out

    def set_user_active(self, user_id: int, active: bool) -> bool:
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE auth_users SET is_active=? WHERE id=? RETURNING id",
                (1 if active else 0, user_id),
            )
            changed = cur.fetchone() is not None
            if changed and not active:
                conn.execute(
                    "UPDATE auth_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",
                    (iso(), user_id),
                )
            conn.commit()
            return changed
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            raise AuthStorageError(str(exc)) from exc
        finally:
            self._close(conn)
