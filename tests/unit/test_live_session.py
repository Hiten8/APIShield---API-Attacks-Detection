"""Tests for live session-id extraction (JWT / header / IP)."""

from __future__ import annotations

import base64
import json

from apishield.behavioral.live_session import decode_jwt_payload, extract_session_id


def _jwt(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode(
        "ascii"
    )
    body = body.rstrip("=")
    return f"aaa.{body}.sig"


def test_explicit_header_wins():
    token = _jwt({"email": "victim@example.com"})
    session = extract_session_id(
        {
            "X-APIShield-Session": "manual-session",
            "Authorization": f"Bearer {token}",
        },
        source_ip="1.2.3.4",
    )
    assert session == "manual-session"


def test_jwt_email_becomes_session():
    token = _jwt({"email": "naruto@example.com", "role": "user"})
    session = extract_session_id(
        {"Authorization": f"Bearer {token}"},
        source_ip="9.9.9.9",
    )
    assert session == "naruto@example.com"
    assert decode_jwt_payload(token)["email"] == "naruto@example.com"


def test_fallback_to_ip_when_unauthenticated():
    session = extract_session_id({}, source_ip="10.0.0.8")
    assert session == "10.0.0.8"
