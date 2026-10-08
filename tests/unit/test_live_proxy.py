"""Unit tests for live GNN proxy scoring (no crAPI)."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock

from apishield.behavioral.infer import SessionScore
from apishield.behavioral.live_proxy import LiveGnnProxy, _merge_expose_headers
from apishield.conformance.openapi_loader import OpenAPILoader
from apishield.conformance.validator import OpenAPIValidator

SPEC = Path("tests/fixtures/openapi/simple_api.yaml")


def _validator() -> OpenAPIValidator:
    return OpenAPIValidator(OpenAPILoader().load(SPEC))


def _jwt(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode(
        "ascii"
    )
    return f"aaa.{body.rstrip('=')}.sig"


def test_score_request_keys_session_from_jwt():
    scorer = MagicMock()
    scorer.apply_event.return_value = None
    scorer.snapshot.return_value = SessionScore(
        session_id="naruto@example.com",
        session_score=0.0,
        flagged=False,
        window_scores=[],
        window_count=0,
    )
    proxy = LiveGnnProxy(
        scorer,
        target_base_url="http://localhost:8888",
        validator=_validator(),
    )
    request = MagicMock()
    request.headers = {
        "authorization": f"Bearer {_jwt({'email': 'naruto@example.com'})}"
    }
    request.client.host = "1.1.1.1"
    request.method = "GET"
    request.url.path = "/workshop/api/shop/products"
    request.query_params = {}

    proxy._score_request(request, 200)

    event = scorer.apply_event.call_args.args[0]
    assert event["session_id"] == "naruto@example.com"
    assert event["path"] == "/workshop/api/shop/products"
    assert event["response_status"] == 200
    assert event["method"] == "GET"


def _request(
    *,
    method: str = "GET",
    path: str = "/api/users/123",
    query: dict | None = None,
    headers: dict | None = None,
    host: str = "1.1.1.1",
) -> MagicMock:
    request = MagicMock()
    request.headers = headers or {}
    request.client.host = host
    request.method = method
    request.url.path = path
    request.query_params = query or {}
    return request


def test_valid_documented_call_is_conformance_ok_and_scored():
    scorer = MagicMock()
    scorer.threshold = 0.5
    scorer.apply_event.return_value = None
    scorer.snapshot.return_value = SessionScore(
        session_id="1.1.1.1",
        session_score=0.0,
        flagged=False,
        window_scores=[],
        window_count=0,
    )
    proxy = LiveGnnProxy(
        scorer,
        target_base_url="http://localhost:8888",
        validator=_validator(),
    )
    record = proxy._observe_request(
        _request(query={"include": "profile"}),
        200,
    )
    assert record["conformance"]["valid"] is True
    assert record["conformance"]["violations"] == []
    assert record["conformance"]["endpoint"] == "/api/users/{id}"
    assert record["gnn"]["waiting"] is True
    assert record["gnn"]["window_score"] is None
    headers = proxy._shield_headers(record)
    assert headers["X-APIShield-Conformance"] == "valid"
    assert headers["X-APIShield-Violation-Count"] == "0"
    assert headers["X-APIShield-GNN-Window"] == ""
    assert headers["X-APIShield-Flagged"] == "false"


def test_unknown_endpoint_and_undocumented_query_are_reported():
    scorer = MagicMock()
    scorer.threshold = 0.5
    scorer.apply_event.return_value = MagicMock(
        window_score=0.32,
        session_score=0.32,
        flagged=False,
        first_flag=False,
    )
    scorer.snapshot.return_value = SessionScore(
        session_id="1.1.1.1",
        session_score=0.32,
        flagged=False,
        window_scores=[0.32],
        window_count=1,
    )
    proxy = LiveGnnProxy(
        scorer,
        target_base_url="http://localhost:8888",
        validator=_validator(),
    )
    unknown = proxy._observe_request(_request(path="/not/in/spec"), 404)
    assert unknown["conformance"]["valid"] is False
    assert unknown["conformance"]["violations"][0]["violation_type"] == (
        "unknown_endpoint"
    )
    assert unknown["gnn"]["window_score"] == 0.32

    extra = proxy._observe_request(
        _request(query={"include": "profile", "is_admin": "true"}),
        200,
    )
    types = {row["violation_type"] for row in extra["conformance"]["violations"]}
    assert extra["conformance"]["valid"] is False
    assert "undocumented_parameter" in types
    assert extra["conformance"]["violations"][0]["parameter"] == "is_admin"

    payload = proxy.calls_payload(limit=10)
    assert payload["count"] == 2
    assert payload["calls"][0]["path"] == "/not/in/spec"


def test_invalid_json_body_is_a_conformance_violation():
    scorer = MagicMock()
    scorer.threshold = 0.5
    scorer.apply_event.return_value = None
    scorer.snapshot.return_value = SessionScore(
        session_id="1.1.1.1",
        session_score=0.0,
        flagged=False,
        window_scores=[],
        window_count=0,
    )
    proxy = LiveGnnProxy(
        scorer,
        target_base_url="http://localhost:8888",
        validator=_validator(),
    )
    record = proxy._observe_request(
        _request(
            method="POST",
            path="/api/users",
            headers={"content-type": "application/json"},
        ),
        400,
        body=b'{"username": "x"}',
    )
    assert record["conformance"]["valid"] is False
    assert any(
        row["violation_type"] == "invalid_request_body"
        or row["location"] == "body"
        for row in record["conformance"]["violations"]
    )


def test_cors_expose_headers_include_apishield_fields():
    headers = {"Access-Control-Expose-Headers": "ETag"}
    _merge_expose_headers(headers)
    value = headers["Access-Control-Expose-Headers"]
    assert "ETag" in value
    assert "X-APIShield-Conformance" in value
    assert "X-APIShield-GNN-Session-Max" in value
