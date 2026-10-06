"""Smoke unit tests for normal-user workflows (no live crAPI required)."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest

from apishield.ingestion.models import APIEvent
from apishield.traffic.workflows import NormalUserWorkflows


def _event(method: str, path: str, status: int = 200) -> APIEvent:
    return APIEvent(
        event_id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        user_id="user@example.com",
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
async def test_shop_workflow_writes_jsonl_and_can_quit_early(
    tmp_path,
    monkeypatch,
):
    output = tmp_path / "workflow.jsonl"
    runner = NormalUserWorkflows(
        output_path=output,
        delay_scale=0.01,
        early_quit_probability=1.0,
    )

    async def fake_request(method, path, params=None, json=None):
        if path.endswith("/login"):
            return (
                _response({"token": "t", "role": "user", "message": "Login successful"}),
                _event(method, path),
            )
        raise AssertionError(f"unexpected request after early quit: {method} {path}")

    monkeypatch.setattr(
        "apishield.traffic.workflows.TargetAPIClient.request",
        AsyncMock(side_effect=fake_request),
    )
    monkeypatch.setattr(
        "apishield.traffic.workflows.asyncio.sleep",
        AsyncMock(),
    )

    events = await runner.run_shop_browse_workflow(
        email="user@example.com",
        password="Password1!",
    )

    assert len(events) == 1
    assert events[0].path == "/identity/api/auth/login"
    assert output.exists()
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.anyio
async def test_vehicle_workflow_records_dashboard_and_vehicles(
    tmp_path,
    monkeypatch,
):
    output = tmp_path / "workflow.jsonl"
    runner = NormalUserWorkflows(
        output_path=output,
        delay_scale=0.01,
        early_quit_probability=0.0,
    )

    async def fake_request(method, path, params=None, json=None):
        if path.endswith("/login"):
            return (
                _response({"token": "t", "role": "user"}),
                _event(method, path),
            )

        if path.endswith("/dashboard"):
            return _response({"id": 1}), _event(method, path)

        if path.endswith("/vehicles"):
            return (
                _response(
                    [
                        {
                            "id": 1,
                            "uuid": "1929186d-8b67-4163-a208-de52a41f7301",
                        }
                    ]
                ),
                _event(method, path),
            )

        if "/location" in path:
            return (
                _response(
                    {
                        "carId": "1",
                        "fullName": "Test",
                        "vehicleLocation": {
                            "id": 1,
                            "latitude": "0",
                            "longitude": "0",
                        },
                    }
                ),
                _event(method, path),
            )

        if path.endswith("/resend_email"):
            return _response({"message": "ok"}), _event(method, path)

        return _response({}), _event(method, path)

    monkeypatch.setattr(
        "apishield.traffic.workflows.TargetAPIClient.request",
        AsyncMock(side_effect=fake_request),
    )
    monkeypatch.setattr(
        "apishield.traffic.workflows.asyncio.sleep",
        AsyncMock(),
    )
    monkeypatch.setattr(
        "apishield.traffic.workflows.random.random",
        MagicMock(return_value=0.10),
    )
    monkeypatch.setattr(
        "apishield.traffic.workflows.random.choice",
        MagicMock(return_value="1929186d-8b67-4163-a208-de52a41f7301"),
    )

    events = await runner.run_vehicle_tracking_workflow(
        email="user@example.com",
        password="Password1!",
    )

    assert any(e.path == "/identity/api/v2/user/dashboard" for e in events)
    assert any(e.path == "/identity/api/v2/vehicle/vehicles" for e in events)
    assert any("/location" in e.path for e in events)
    assert output.exists()
    assert len(output.read_text(encoding="utf-8").splitlines()) == len(events)
