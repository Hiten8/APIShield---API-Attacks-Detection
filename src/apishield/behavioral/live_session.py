"""Identify a live session from HTTP headers (JWT / explicit header / IP)."""

from __future__ import annotations

import base64
import json
from typing import Mapping


def decode_jwt_payload(token: str) -> dict:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def extract_session_id(
    headers: Mapping[str, str],
    *,
    source_ip: str | None = None,
) -> str:
    """
    Prefer X-APIShield-Session, then JWT email/sub, then client IP.

    Login requests have no Bearer token yet; they share a session with later
    authenticated calls once the same JWT appears, or stay on IP until then.
    """

    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    explicit = lowered.get("x-apishield-session")
    if explicit:
        return explicit.strip()

    auth = lowered.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        payload = decode_jwt_payload(token)
        for key in ("email", "sub", "user_id", "username"):
            value = payload.get(key)
            if value:
                return str(value)
        if token:
            return f"jwt:{token[:24]}"

    if source_ip:
        return source_ip
    return "anonymous"
