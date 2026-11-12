"""Apple Push Notification service client (token auth, HTTP/2) and payload encryption."""

from __future__ import annotations

import base64
import json
import os
import ssl
import time
from dataclasses import dataclass

import httpx
import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key

PRODUCTION = "api.push.apple.com"
SANDBOX = "api.sandbox.push.apple.com"


class KeyError_(Exception):
    """The .p8 key could not be read."""


def load_key(path: str):
    """Read the APNs signing key from disk (blocking: run in the executor)."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as err:
        raise KeyError_("missing") from err
    try:
        return load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as err:
        raise KeyError_("invalid") from err


def encrypt(key_b64: str, payload: dict) -> str:
    """AES-256-GCM, laid out as CryptoKit's SealedBox.combined: nonce(12) | ciphertext | tag(16)."""
    key = base64.b64decode(key_b64)
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, json.dumps(payload, ensure_ascii=False).encode(), None)
    return base64.b64encode(nonce + sealed).decode()


@dataclass
class Result:
    status: int
    reason: str | None

    @property
    def ok(self) -> bool:
        return self.status == 200

    @property
    def gone(self) -> bool:
        """The phone no longer accepts notices with this token."""
        return self.status == 410 or self.reason in ("Unregistered", "DeviceTokenNotForTopic")


class APNs:
    """Sends notices signed with the team's APNs key."""

    def __init__(self, key, key_id: str, team_id: str, topic: str, ssl_context: ssl.SSLContext) -> None:
        self._key = key
        self._key_id = key_id
        self._team_id = team_id
        self.topic = topic
        self._jwt: str | None = None
        self._jwt_at = 0.0
        self._client = httpx.AsyncClient(http2=True, verify=ssl_context, timeout=15)

    async def close(self) -> None:
        await self._client.aclose()

    def _token(self) -> str:
        # Apple wants the token refreshed at most every 20 min and at least every 60 min.
        now = time.time()
        if self._jwt is None or now - self._jwt_at > 45 * 60:
            self._jwt = jwt.encode({"iss": self._team_id, "iat": int(now)}, self._key,
                                   algorithm="ES256", headers={"kid": self._key_id})
            self._jwt_at = now
        return self._jwt

    async def send(self, device_token: str, payload: dict, *, sandbox: bool, push_type: str = "alert",
                   priority: int = 10, collapse_id: str | None = None) -> Result:
        headers = {
            "authorization": f"bearer {self._token()}",
            "apns-topic": self.topic,
            "apns-push-type": push_type,
            "apns-priority": str(priority),
        }
        if collapse_id:
            headers["apns-collapse-id"] = collapse_id[:64]
        url = f"https://{SANDBOX if sandbox else PRODUCTION}/3/device/{device_token}"
        try:
            resp = await self._client.post(url, content=json.dumps(payload, separators=(",", ":")).encode(), headers=headers)
        except httpx.HTTPError as err:
            return Result(0, type(err).__name__)
        reason = None
        if resp.status_code != 200:
            try:
                reason = resp.json().get("reason")
            except ValueError:
                reason = resp.text[:100]
        return Result(resp.status_code, reason)
