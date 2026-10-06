"""Unit tests for shop attack workflows (mocked HTTP)."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest

from apishield.ingestion.models import APIEvent
from apishield.traffic.attacks import ShopAttackWorkflows


def _event(method: str, path: str, status: int = 200) -> APIEvent:
    return APIEvent(
        event_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        user_id="attacker",
        method=method,
        path=path,
        endpoint=path,
        response_status=status,
        target_service="crapi",
    )


def _response(payload: dict | list, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        json=payload,
        request=httpx.Request("GET", "http://localhost:8888/"),
    )


@pytest.mark.anyio
async def test_order_enumeration_keeps_many_order_gets(tmp_path, monkeypatch):
    output = tmp_path / "shop_order_enumeration.jsonl"
    runner = ShopAttackWorkflows(delay_scale=0.01)

    async def fake_request(method, path, params=None, json=None):
        if path.endswith("/login"):
            return (
                _response({"token": "t", "role": "user"}),
                _event(method, path),
            )
        if path.endswith("/products"):
            return (
                _response({"credit": 100, "products": [{"id": 1}, {"id": 2}]}),
                _event(method, path),
            )
        if path.endswith("/orders/all"):
            return (
                _response({"orders": [{"id": 3}, {"id": 4}]}),
                _event(method, path),
            )
        if "/orders/" in path:
            # Simulate foreign IDs often failing authz — still recorded.
            status = 403 if path.rstrip("/").split("/")[-1].isdigit() else 200
            try:
                oid = int(path.rstrip("/").split("/")[-1])
                status = 200 if oid in {3, 4} else 403
            except ValueError:
                status = 404
            return _response({"message": "x"}, status), _event(method, path, status)
        return _response({}), _event(method, path)

    monkeypatch.setattr(
        "apishield.traffic.attacks.TargetAPIClient.request",
        AsyncMock(side_effect=fake_request),
    )
    monkeypatch.setattr("apishield.traffic.attacks.asyncio.sleep", AsyncMock())
    # Force a deterministic-ish large scan shape.
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.choice",
        MagicMock(
            side_effect=[
                "none",  # cover
                "foreign",  # id mode
                "sequential",  # strategy
            ]
        ),
    )
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.randint",
        MagicMock(side_effect=[1, 20]),  # start=1, count=20
    )
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.random",
        MagicMock(return_value=0.99),  # no mid orders/all
    )

    events = await runner.run_order_enumeration_attack(
        "a@example.com",
        "Password1!",
        user_id="attacker",
        output_path=output,
    )

    order_gets = [
        e
        for e in events
        if e.method == "GET"
        and "/shop/orders/" in e.path
        and not e.path.endswith("/all")
    ]
    assert events[0].path.endswith("/login")
    assert len(order_gets) >= 15
    assert output.exists()
    assert len(output.read_text(encoding="utf-8").splitlines()) == len(events)


@pytest.mark.anyio
async def test_order_flooder_keeps_many_posts(tmp_path, monkeypatch):
    output = tmp_path / "shop_order_flooder.jsonl"
    runner = ShopAttackWorkflows(delay_scale=0.01)

    async def fake_request(method, path, params=None, json=None):
        if path.endswith("/login"):
            return (
                _response({"token": "t", "role": "user"}),
                _event(method, path),
            )
        if path.endswith("/products"):
            return (
                _response({"credit": 100, "products": [{"id": 1}, {"id": 2}]}),
                _event(method, path),
            )
        if path.endswith("/orders") and method.upper() == "POST":
            return (
                _response({"id": 99, "message": "ok", "credit": 1}),
                _event(method, path),
            )
        if path.endswith("/orders/all"):
            return _response({"orders": [{"id": 99}]}), _event(method, path)
        if "/orders/" in path:
            return _response({"orders": {"id": 99}}), _event(method, path)
        return _response({}), _event(method, path)

    monkeypatch.setattr(
        "apishield.traffic.attacks.TargetAPIClient.request",
        AsyncMock(side_effect=fake_request),
    )
    monkeypatch.setattr("apishield.traffic.attacks.asyncio.sleep", AsyncMock())
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.random",
        MagicMock(return_value=0.10),  # fetch products
    )

    def fake_randint(a, b):
        if (a, b) == (10, 40):
            return 12
        if (a, b) == (1, 3):
            return 1
        return a

    def fake_choice(seq):
        seq = list(seq)
        if seq == ["fixed", "round_robin"]:
            return "fixed"
        if seq == ["none", "orders_all", "last_order"]:
            return "none"
        return seq[0]

    monkeypatch.setattr(
        "apishield.traffic.attacks.random.randint",
        MagicMock(side_effect=fake_randint),
    )
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.choice",
        MagicMock(side_effect=fake_choice),
    )

    events = await runner.run_order_flooder_attack(
        "a@example.com",
        "Password1!",
        user_id="attacker",
        output_path=output,
    )

    posts = [
        e
        for e in events
        if e.method == "POST" and e.path == "/workshop/api/shop/orders"
    ]
    assert len(posts) >= 10
    assert output.exists()
