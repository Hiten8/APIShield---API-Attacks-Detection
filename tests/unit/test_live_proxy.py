"""Unit tests for live GNN proxy scoring (no crAPI)."""

from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock

from apishield.behavioral.infer import SessionScore
from apishield.behavioral.live_proxy import LiveGnnProxy


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
    proxy = LiveGnnProxy(scorer, target_base_url="http://localhost:8888")
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
