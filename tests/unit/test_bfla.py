"""Unit tests for workshop BFLA privileged-function probes."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest

from apishield.ingestion.models import APIEvent
from apishield.traffic.attacks import BFLA_PROBE_KINDS, ShopAttackWorkflows


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
async def test_bfla_hits_sampled_privileged_endpoints(tmp_path, monkeypatch):
    output = tmp_path / "shop_workshop_bfla.jsonl"
    runner = ShopAttackWorkflows(delay_scale=0.01)

    async def fake_request(method, path, params=None, json=None):
        if path.endswith("/login"):
            return (
                _response({"token": "t", "role": "user"}),
                _event(method, path),
            )
        return _response({"ok": True}), _event(method, path)

    monkeypatch.setattr(
        "apishield.traffic.attacks.TargetAPIClient.request",
        AsyncMock(side_effect=fake_request),
    )
    monkeypatch.setattr("apishield.traffic.attacks.asyncio.sleep", AsyncMock())
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.choice",
        MagicMock(return_value="none"),
    )
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.random",
        MagicMock(return_value=0.99),
    )

    def fake_randint(a, b):
        if (a, b) == (1, len(BFLA_PROBE_KINDS)):
            return 4
        if (a, b) == (1, 2):
            return 1
        if (a, b) == (1, 3):
            return 2
        return a

    def fake_sample(population, k):
        seq = list(population)
        if seq == list(BFLA_PROBE_KINDS):
            return seq[:k]
        return seq[:k]

    monkeypatch.setattr(
        "apishield.traffic.attacks.random.randint",
        MagicMock(side_effect=fake_randint),
    )
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.sample",
        MagicMock(side_effect=fake_sample),
    )

    events = await runner.run_workshop_bfla_attack(
        "a@example.com",
        "Password1!",
        user_id="attacker",
        output_path=output,
    )

    paths = [e.path for e in events]
    assert paths[0].endswith("/login")
    assert "/workshop/api/management/users/all" in paths
    assert "/workshop/api/mechanic/" in paths
    assert "/workshop/api/mechanic/service_requests" in paths
    assert "/workshop/api/mechanic/mechanic_report" in paths
    assert output.exists()
    assert len(output.read_text(encoding="utf-8").splitlines()) == len(events)


@pytest.mark.anyio
async def test_bfla_random_subset_can_be_single_endpoint(tmp_path, monkeypatch):
    output = tmp_path / "shop_workshop_bfla.jsonl"
    runner = ShopAttackWorkflows(delay_scale=0.01)

    async def fake_request(method, path, params=None, json=None):
        if path.endswith("/login"):
            return (
                _response({"token": "t", "role": "user"}),
                _event(method, path),
            )
        return _response({"ok": True}), _event(method, path)

    monkeypatch.setattr(
        "apishield.traffic.attacks.TargetAPIClient.request",
        AsyncMock(side_effect=fake_request),
    )
    monkeypatch.setattr("apishield.traffic.attacks.asyncio.sleep", AsyncMock())
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.choice",
        MagicMock(return_value="none"),
    )
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.random",
        MagicMock(return_value=0.99),
    )
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.randint",
        MagicMock(return_value=1),
    )
    monkeypatch.setattr(
        "apishield.traffic.attacks.random.sample",
        MagicMock(return_value=["users_all"]),
    )

    events = await runner.run_workshop_bfla_attack(
        "a@example.com",
        "Password1!",
        user_id="attacker",
        output_path=output,
    )

    privileged = [
        e.path
        for e in events
        if e.path
        in {
            "/workshop/api/management/users/all",
            "/workshop/api/mechanic/",
            "/workshop/api/mechanic/service_requests",
            "/workshop/api/mechanic/mechanic_report",
        }
    ]
    assert privileged == ["/workshop/api/management/users/all"]
