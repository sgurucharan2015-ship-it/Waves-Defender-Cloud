from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any


class StatelessAuthError(Exception):
    pass


@dataclass(slots=True)
class Principal:
    kind: str  # "master" or "api_key"
    kid: str | None = None
    name: str | None = None
    issued_at: int | None = None
    expires_at: int | None = None
    epoch: int | None = None
    is_admin: bool = False


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * ((4 - len(text) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except Exception as exc:
        raise StatelessAuthError("Malformed API key") from exc


class StatelessKeyManager:
    """Zero-database Waves API key issuer/verifier.

    Keys are signed with HMAC-SHA256 using WAVES_SIGNING_SECRET from the server
    environment. No user account, password, session, key hash, usage counter, or
    token registry is stored anywhere.

    Optional revocation controls are also environment-only:
      WAVES_KEY_EPOCH=1
        Incrementing this invalidates every previously issued user API key.

      WAVES_REVOKED_KIDS=kid1,kid2
        Rejects specific key IDs. This is intended as a small manual deny-list,
        not a database replacement.
    """

    PREFIX = "waves_sk_v1"

    def __init__(self) -> None:
        self.secret = os.getenv("WAVES_SIGNING_SECRET", "").strip()
        try:
            self.epoch = max(1, int(os.getenv("WAVES_KEY_EPOCH", "1")))
        except ValueError:
            self.epoch = 1
        try:
            self.default_days = max(1, int(os.getenv("WAVES_DEFAULT_KEY_DAYS", "365")))
        except ValueError:
            self.default_days = 365
        try:
            self.max_days = max(self.default_days, int(os.getenv("WAVES_MAX_KEY_DAYS", "3650")))
        except ValueError:
            self.max_days = max(self.default_days, 3650)
        self.revoked_kids = {
            x.strip()
            for x in os.getenv("WAVES_REVOKED_KIDS", "").split(",")
            if x.strip()
        }

    def configured(self) -> bool:
        # 32 characters is a floor, not a cryptographic byte-count guarantee.
        # README generates a 48-byte URL-safe random secret.
        return len(self.secret) >= 32

    def status(self) -> dict[str, Any]:
        return {
            "backend": "stateless-hmac-sha256",
            "configured": self.configured(),
            "database_required": False,
            "key_epoch": self.epoch,
            "default_key_days": self.default_days,
            "max_key_days": self.max_days,
            "revoked_key_ids": len(self.revoked_kids),
        }

    def _require_configured(self) -> None:
        if not self.configured():
            raise StatelessAuthError(
                "WAVES_SIGNING_SECRET is missing or too short; use at least 32 random characters"
            )

    def _sign(self, payload_b64: str) -> str:
        self._require_configured()
        digest = hmac.new(
            self.secret.encode("utf-8"),
            payload_b64.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return _b64url_encode(digest)

    def create_key(self, name: str = "Default", days: int | None = None) -> tuple[dict[str, Any], str]:
        self._require_configured()
        now = int(time.time())
        lifetime = self.default_days if days is None else int(days)
        if lifetime < 1:
            raise StatelessAuthError("Key lifetime must be at least 1 day")
        if lifetime > self.max_days:
            raise StatelessAuthError(f"Key lifetime cannot exceed {self.max_days} days")

        clean_name = (name or "Default").strip()[:64] or "Default"
        kid = secrets.token_urlsafe(9)
        exp = now + lifetime * 86400
        payload = {
            "v": 1,
            "kid": kid,
            "name": clean_name,
            "iat": now,
            "exp": exp,
            "epoch": self.epoch,
        }
        payload_raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_b64 = _b64url_encode(payload_raw)
        signature = self._sign(payload_b64)
        token = f"{self.PREFIX}.{payload_b64}.{signature}"
        return self._public_meta(payload), token

    @staticmethod
    def _public_meta(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "kid": payload["kid"],
            "name": payload.get("name", "Default"),
            "issued_at_unix": int(payload["iat"]),
            "expires_at_unix": int(payload["exp"]),
            "epoch": int(payload["epoch"]),
        }

    def verify(self, token: str) -> Principal | None:
        if not token or not self.configured():
            return None
        parts = token.strip().split(".")
        if len(parts) != 3 or parts[0] != self.PREFIX:
            return None
        payload_b64, supplied_sig = parts[1], parts[2]
        try:
            expected_sig = self._sign(payload_b64)
            if not hmac.compare_digest(supplied_sig, expected_sig):
                return None
            payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
            if int(payload.get("v", 0)) != 1:
                return None
            kid = str(payload.get("kid", ""))
            if not kid or kid in self.revoked_kids:
                return None
            epoch = int(payload.get("epoch", 0))
            if epoch != self.epoch:
                return None
            iat = int(payload.get("iat", 0))
            exp = int(payload.get("exp", 0))
            now = int(time.time())
            # Reject impossible/future-issued keys and expired keys.
            if iat <= 0 or iat > now + 300 or exp <= now or exp <= iat:
                return None
            return Principal(
                kind="api_key",
                kid=kid,
                name=str(payload.get("name", "Default"))[:64],
                issued_at=iat,
                expires_at=exp,
                epoch=epoch,
                is_admin=False,
            )
        except Exception:
            return None

    def inspect(self, token: str) -> dict[str, Any] | None:
        principal = self.verify(token)
        if not principal:
            return None
        return {
            "kind": principal.kind,
            "kid": principal.kid,
            "name": principal.name,
            "issued_at_unix": principal.issued_at,
            "expires_at_unix": principal.expires_at,
            "epoch": principal.epoch,
            "is_admin": principal.is_admin,
        }
