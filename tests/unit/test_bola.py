"""Unit tests for shop order BOLA ownership + multi-victim access plan."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest

from apishield.ingestion.models import APIEvent
from apishield.traffic.attacks import ShopAttackWorkflows

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from generate_attack_traffic import _build_bola_access_plan  # noqa: E402


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
async def test_collect_order_ownership_writes_json(tmp_path, monkeypatch):
    ownership_path = tmp_path / "order_ownership.json"
    runner = ShopAttackWorkflows(delay_scale=0.01)

    users = [
        {
            "name": "alice",
            "email": "alice@example.com",
            "password": "Password1!",
        },
        {
            "name": "bob",
            "email": "bob@example.com",
            "password": "Password1!",
        },
    ]

    async def fake_request(method, path, params=None, json=None):
        if path.endswith("/login"):
            return (
                _response({"token": "t", "role": "user"}),
                _event(method, path),
            )
        if path.endswith("/orders/all"):
            if (params or {}).get("offset", 0) == 0:
                return (
                    _response({"orders": [{"id": 11}, {"id": 12}]}),
                    _event(method, path),
                )
            return _response({"orders": []}), _event(method, path)
        return _response({}), _event(method, path)

    monkeypatch.setattr(
        "apishield.traffic.attacks.TargetAPIClient.request",
        AsyncMock(side_effect=fake_request),
    )

    ownership = await runner.collect_order_ownership(
        users,
        ownership_path=ownership_path,
    )

    assert ownership_path.exists()
    assert ownership["users"]["alice"]["order_ids"] == [11, 12]
    assert ownership["users"]["bob"]["order_count"] == 2


def test_build_access_plan_ordered_is_user_then_object():
    victims = [
        {"name": "v1", "email": "v1@example.com", "password": "x"},
        {"name": "v2", "email": "v2@example.com", "password": "x"},
    ]
    owned = {
        "v1": [1, 2],
        "v2": [3],
    }
    plan = _build_bola_access_plan(victims, owned, traversal="ordered")
    assert plan == [("v1", 1), ("v1", 2), ("v2", 3)]


@pytest.mark.anyio
async def test_bola_skips_and_hits_plan_ids(tmp_path, monkeypatch):
    output = tmp_path / "shop_order_bola.jsonl"
    runner = ShopAttackWorkflows(delay_scale=0.01)

    async def fake_request(method, path, params=None, json=None):
        if path.endswith("/login"):
            return (
                _response({"token": "t", "role": "user"}),
                _event(method, path),
            )
        return _response({"orders": {"id": 1}}), _event(method, path)

    monkeypatch.setattr(
        "apishield.traffic.attacks.TargetAPIClient.request",
        AsyncMock(side_effect=fake_request),
    )
    monkeypatch.setattr("apishield.traffic.attacks.asyncio.sleep", AsyncMock())
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.choice",
        MagicMock(side_effect=["none", "get_only"]),
    )
    # Never skip, no trailing
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.random",
        MagicMock(return_value=0.99),
    )

    attacker = {
        "name": "attacker",
        "email": "a@example.com",
        "password": "Password1!",
    }
    access_plan = [("v1", 21), ("v1", 22), ("v2", 23)]

    events = await runner.run_order_bola_attack(
        attacker,
        access_plan,
        output_path=output,
        skip_probability=0.05,
        traversal="ordered",
    )

    order_gets = [
        e
        for e in events
        if e.method == "GET"
        and "/shop/orders/" in e.path
        and not e.path.endswith("/all")
    ]
    ids = [int(e.path.rstrip("/").split("/")[-1]) for e in order_gets]
    assert ids == [21, 22, 23]
    assert output.exists()
